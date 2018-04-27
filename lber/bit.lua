local bit = {}

if _G._VERSION >= "Lua 5.3" then
	load([[
		local bit = ...
		function bit.band(a, b)
			return a & b
		end

		function bit.bor(a, b)
			return a | b
		end

		function bit.rshift(a, b)
			return a >> b
		end

		function bit.lshift(a, b)
			return a << b
		end
	]])(bit)
elseif pcall(require, "bit") then
	local bitlib = require "bit"

	bit.band = bitlib.band
	bit.bor = bitlib.bor
	bit.rshift = bitlib.rshift
	bit.lshift = bitlib.lshift
else
	function bit.band(a, b)
		local out = 0

		for off = 0, math.huge do
			if a == 0 or b == 0 then
				break
			end

			if a % 2 == 1 and b % 2 == 1 then
				out = out + 2^off
			end

			a, b = math.floor(a / 2), math.floor(b / 2)
		end

		return out
	end

	function bit.bor(a, b)
		local out = 0

		for off = 0, math.huge do
			if a == 0 and b == 0 then
				break
			end

			if a % 2 == 1 or b % 2 == 1 then
				out = out + 2^off
			end

			a, b = math.floor(a / 2), math.floor(b / 2)
		end

		return out
	end

	function bit.rshift(a, b)
		return math.floor(a / 2^b)
	end

	function bit.lshift(a, b)
		return a * 2^b
	end
end

function bit.addOctetBE(value, octet)
	return bit.bor(
		bit.lshift(value, 8),
		octet)
end

return bit
