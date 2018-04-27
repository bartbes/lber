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

-- TODO: All DER/CER limitation
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
	[0x1A] = { name = "VisibleString" },
	[0x1B] = { name = "GeneralString" },
	[0x1C] = { name = "UniversalString" },
	[0x1D] = { name = "CHARACTER STRING", der = { forcePrimitive = true } },
	[0x1E] = { name = "BMPString" },
}

for i = 0x00, 0x1E do
	local v = universalTypes[i]
	if v then
		universalTypes[v.name] = v
	end
end

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

universalTypes["BOOLEAN"].decode = function(tlv)
	assert(tlv.length == 1, "Invalid BOOLEAN encoding")

	local value = string.byte(tlv.value)
	if tlv.mode == 'cer' or tlv.mode == 'der' then
		assert(value == 255 or value == 0, "Invalid BOOLEAN encoding")
	end
	tlv.decoded = value ~= 0
end

universalTypes["INTEGER"].decode = function(tlv)
	-- TODO: bignum?
	local value = 0
	for i = 1, #tlv.value do
		value = bit.addOctetBE(value, string.byte(tlv.value, i))
	end
	-- TODO two's complement
	tlv.decoded = value
end
universalTypes["ENUMERATED"].decode = universalTypes["INTEGER"].decode

universalTypes["REAL"].decode = function(tlv)
	if #tlv.value then -- +0
		tlv.decoded = 0
		return
	end

	local handle = lber.handle.fromString(tlv.value)
	local first = lber.handle.readByte(handle)
	if bit.band(first, 0x80) == 0x80 then
		local sign = bit.band(first, 0x40) == 1 and -1 or 1
		local base = bit.band(first, 0x30)
		if base == 0x00 then
			base = 2
		elseif base == 0x10 then
			base = 8
		elseif base == 0x20 then
			base = 16
		else
			error("Invalid base for REAL")
		end
		local factor = bit.rshift(bit.band(first, 0x0C), 2)
		local exponentFormat = bit.band(first, 0x03)
		local exponentOctets = exponentFormat + 1
		if exponentFormat == 0x03 then
			exponentOctets = lber.handle.readByte()
			assert(exponentOctets > 0, "Invalid exponent format for REAL")
		end

		local exponent = 0
		for _ = 1, exponentOctets do
			exponent = bit.addOctetBE(exponent, lber.handle.readByte(handle))
		end
		-- TODO: Verify exponent
		-- TODO: two's complement

		local number = 0
		while not lber.handle.isEof() do
			number = bit.addOctetBE(number, lber.handle.readByte(handle))
		end

		local mantissa = sign * number * 2^factor
		tlv.value = base ^ exponent * mantissa
	elseif bit.band(first, 0xC0) == 0x00 then
		-- TODO: decimal (ISO-6093)
	elseif bit.band(first, 0xC0) == 0x40 then
		if first == 0x40 then
			tlv.value = math.huge
		elseif first == 0x41 then
			tlv.value = -math.huge
		elseif first == 0x42 then
			tlv.value = math.abs(0/0) -- nan
		elseif first == 0x43 then
			tlv.value = -0
		end
	end
end

universalTypes["BIT STRING"].decode = function(rootTLV)
	local function decode(tlv)
		assert(tlv.type.class == "universal" and
			tlv.type.tagNumber == 0x03,
			"Invalid BIT STRING encoding")

		local handle = lber.handle.fromString(tlv.value)
		if not tlv.type.isConstructed then
			local unused = lber.handle.readByte(handle)
			local bits = 0

			local value = 0
			while not lber.handle.isEof(handle) do
				value = bit.addOctetBE(value, lber.handle.readByte(handle))
				bits = bits + 8
			end

			return bit.rshift(value, unused), bits - unused
		else
			local value, bits = 0, 0

			while not lber.handle.isEof(handle) do
				local subTLV = lber.parseTLV(handle, tlv.mode)
				if subTLV.type.class == "universal" and
						subTLV.type.tagNumber == 0x00 then -- EOC
					break
				end

				local subValue, subBits = decode(subTLV)

				value = bit.bor(
					bit.lshift(value, subBits),
					subValue)
				bits = bits + subBits
			end
		end
	end

	rootTLV.decoded = decode(rootTLV)
end

universalTypes["OCTET STRING"].decode = function(tlv)
	if not tlv.type.isConstructed then
		tlv.decoded = tlv.value
	else
		local handle = lber.handle.fromString(tlv.value)
		local parts = {}

		while not lber.handle.isEof(handle) do
			local subTLV = lber.parseTLV(handle, tlv.mode)
			assert(subTLV.type.class == "universal", "Invalid constructed OCTET STRING encoding")
			if subTLV.type.tagNumber == 0x00 then -- EOC
				break
			end
			assert(subTLV.type.tagNumber == 0x04, "Invalid constructed OCTET STRING encoding")

			universalTypes["OCTET STRING"].decode(subTLV)
			table.insert(parts, subTLV.decoded)
		end

		tlv.decoded = table.concat(parts)
	end
end

universalTypes["NULL"].decode = function(tlv)
	assert(tlv.length == 0, "Invalid NULL encoding")
end

universalTypes["SEQUENCE"].decode = function(tlv)
	local handle = lber.handle.fromString(tlv.value)
	local parts = {}

	while not lber.handle.isEof(handle) do
		local subTLV = lber.parseTLV(handle, tlv.mode)
		lber.tryDecode(subTLV)
		table.insert(parts, subTLV)
	end

	tlv.decoded = parts
end
-- TODO: DER required sorting
universalTypes["SET"].decode = universalTypes["SEQUENCE"].decode

universalTypes["OBJECT IDENTIFIER"].decode = function(tlv)
	universalTypes["RELATIVE-OID"].decode(tlv)

	local parts = tlv.decoded

	-- Split the first part, as it is special
	local first = math.floor(parts[1]/40)
	first = math.min(first, 2)
	parts[1] = parts[1] - first*40
	table.insert(parts, 1, first)

	parts.str = table.concat(parts, ".")
end

universalTypes["RELATIVE-OID"].decode = function(tlv)
	local handle = lber.handle.fromString(tlv.value)
	local parts = {}

	local current = 0
	while not lber.handle.isEof(handle) do
		local octet = lber.handle.readByte(handle)
		current = bit.bor(
			bit.lshift(current, 7), -- NOTE: 7 bits, not 8
			bit.band(octet, 0x7F))

		if bit.band(octet, 0x80) == 0x00 then
			table.insert(parts, current)
			current = 0
		end
	end

	assert(current == 0, "Unfinished OBJECT IDENTIFIER encoding")

	parts.str = table.concat(parts, ".")
	tlv.decoded = parts
end

local function decodeString(tlv)
	if not tlv.type.isConstructed then
		return tlv.value
	else
		local handle = lber.handle.fromString(tlv.value)
		local parts = {}

		while not lber.handle.isEof(handle) do
			local subTLV = lber.parseTLV(handle, tlv.mode)
			assert(subTLV.type.class == tlv.type.class, "Invalid constructed string encoding")
			if subTLV.type.tagNumber == 0x00 then -- EOC
				break -- TODO: reject in DER?
			end
			assert(subTLV.type.tagNumber == tlv.type.tagNumber, "Invalid constructed string encoding")

			table.insert(parts, decodeString(subTLV))
		end

		return table.concat(parts)
	end
end

universalTypes["UTF8String"].decode = function(tlv)
	-- TODO: Validate and special encoding rules?
	tlv.decoded = decodeString(tlv)
end

universalTypes["PrintableString"].decode = function(tlv)
	-- TODO: Validate and special encoding rules?
	tlv.decoded = decodeString(tlv)
end

local function decodeTime(tlv)
	local str = decodeString(tlv)
	-- TODO: ensure utf8
	return str
end

universalTypes["UTCTime"].decode = function(tlv)
	tlv.decoded = decodeTime(tlv)
end

function lber.tryDecode(tlv)
	if tlv.type.class ~= "universal" then
		return
	end

	local uType = universalTypes[tlv.type.tagNumber]
	if uType and uType.decode then
		uType.decode(tlv)
	end
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
