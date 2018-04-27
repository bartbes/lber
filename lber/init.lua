local subrequire
do
	local prefix = (...):match("(.*)%.init$") or (...)
	prefix = prefix .. "."

	function subrequire(modname)
		return require(prefix .. modname)
	end
end

local bit = subrequire "bit"

local lber = {}
lber.handle = subrequire "handle"

-- TODO: A way to handle errors

-- TODO: CER limitations
local universalTypes =
{
	[0x00] = { name = "EOF", forcePrimitive = true },
	[0x01] = { name = "BOOLEAN", forcePrimitive = true },
	[0x02] = { name = "INTEGER", forcePrimitive = true },
	[0x03] = { name = "BIT STRING", der = { forcePrimitive = true } },
	[0x04] = { name = "OCTET STRING", der = { forcePrimitive = true } },
	[0x05] = { name = "NULL", forcePrimitive = true },
	[0x06] = { name = "OBJECT IDENTIFIER", forcePrimitive = true },
	[0x07] = { name = "Object Descriptor" },
	[0x08] = { name = "EXTERNAL", forceConstructed = true },
	[0x09] = { name = "REAL", forcePrimitive = true },
	[0x0A] = { name = "ENUMERATED", forcePrimitive = true },
	[0x0B] = { name = "EMBEDDED PDV", forceConstructed = true },
	[0x0C] = { name = "UTF8String" },
	[0x0D] = { name = "RELATIVE-OID", forcePrimitive = true },
	[0x10] = { name = "SEQUENCE", forceConstructed = true },
	[0x11] = { name = "SET", forceConstructed = true, der = { sorted = true } },
	[0x12] = { name = "NumericString" },
	[0x13] = { name = "PrintableString" },
	[0x14] = { name = "T61String" },
	[0x15] = { name = "VideotexString" },
	[0x16] = { name = "IA5String" },
	[0x17] = { name = "UTCTime" },
	[0x18] = { name = "GeneralizedTime" },
	[0x19] = { name = "GraphicString" },
	[0x1a] = { name = "VisibleString" },
	[0x1b] = { name = "GeneralString" },
	[0x1c] = { name = "UniversalString" },
	[0x1d] = { name = "CHARACTER STRING", der = { forcePrimitive = true } },
	[0x1e] = { name = "BMPString" },
}

local function hasLimitation(type, mode, limitation)
	if not type then return end

	if type[mode] and type[mode][limitation] ~= nil then
		return type[mode][limitation]
	end

	return type[limitation]
end

function lber.parseType(handle, mode)
	local type = {}

	local first = lber.handle.readByte(handle)
	local tagClass = bit.rshift(bit.band(first, 0xC0), 6)

	type.tagNumber = bit.band(first, 0x1F)
	type.isConstructed = bit.band(first, 0x20) ~= 0

	if tagClass == 0 then
		type.class = "universal"

		local uType = universalTypes[type.tagNumber]
		if uType then
			type.name = uType.name
		end

		if hasLimitation(uType, mode, 'forcePrimitive') and type.isConstructed then
			error("Type must be primitive, is constructed")
		elseif hasLimitation(uType, mode, 'forceConstructed') and not type.isConstructed then
			error("Type must be constructed, is primitive")
		end
	elseif tagClass == 1 then
		type.class = "application"
	elseif tagClass == 2 then
		type.class = "context-specific"
	elseif tagClass == 3 then
		type.class = "private"
	end

	if type.tagNumber == 31 then
		assert(tagClass ~= 0, "Invalid universal tag number")

		local tagNumber = 0

		while true do
			local byte = lber.handle.readByte(handle)

			local newValue = bit.band(byte, 0x7F)
			assert(newValue ~= 0, "Invalid type encoding")

			tagNumber = bit.bor(
				bit.lshift(tagNumber, 7),
				newValue)

			if bit.band(byte, 0x80) == 0 then
				break
			end
		end

		type.tagNumber = tagNumber
	end

	return type
end

function lber.parseLength(handle, mode)
	local first = lber.handle.peekByte(handle)

	if first == 0xFF then
		error("Invalid length encoding")
	elseif bit.band(first, 0x80) == 0 then
		-- mode ~= cer?
		return lber.parseLengthDefiniteShort(handle)
	elseif bit.band(first, 0x7F) ~= 0 then
		assert(mode ~= 'cer', "Invalid length encoding")
		return lber.parseLengthDefiniteLong(handle)
	else
		assert(mode ~= 'der', "Invalid length encoding")
		return lber.parseLengthIndefinite(handle)
	end
end

function lber.parseLengthDefiniteShort(handle)
	return lber.handle.readByte(handle)
end

function lber.parseLengthDefiniteLong(handle)
	local first = lber.handle.readByte(handle)
	local numOctets = bit.band(first, 0x7F)

	local result = 0
	for _ = 1, numOctets do
		result = bit.addOctetBE(result, lber.handle.readByte(handle))
	end

	return result
end

function lber.parseLengthIndefinite(_)
	return "indefinite" -- TODO: Try to find the length? Defer this to later?
end

function lber.parseTLV(handle, mode)
	local tlv = {}
	tlv.mode = mode or 'ber'

	tlv.type = lber.parseType(handle)
	tlv.length = lber.parseLength(handle, tlv.mode)

	assert(tlv.length ~= "indefinite", "NYI")
	-- TODO: If not using indefinite encoding, error on EOF

	tlv.value = lber.handle.read(handle, tlv.length)

	return tlv
end

return lber
