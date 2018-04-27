local bit = require "lber.bit"

describe("The bit module", function()
	it("supports and", function()
		for i = 0, 255, 5 do
			assert.are.equal(i, bit.band(i, 0xFF))
		end

		assert.are.equal(66, bit.band(98, 194))
	end)

	it("supports or", function()
		for i = 0, 255, 5 do
			assert.are.equal(0xFF, bit.bor(i, 0xFF))
		end

		assert.are.equal(226, bit.bor(98, 194))
	end)

	it("supports left shift", function()
		for i = 0, 15 do
			assert.are.equal(5 * 2^i, bit.lshift(5, i))
		end

		assert.are.equal(784, bit.lshift(98, 3))
		assert.are.equal(99328, bit.lshift(194, 9))
	end)

	it("supports right shift", function()
		for i = 0, 15 do
			assert.are.equal(
				math.floor(5 / 2^i),
				bit.rshift(5, i))
		end

		assert.are.equal(12, bit.rshift(98, 3))
		assert.are.equal(0, bit.rshift(194, 9))
	end)

	assert.are.equal(8287,
		bit.bor(
			bit.rshift(
				bit.band(
					bit.lshift(6315, 2),
					2218),
				1),
			8283))
end)
