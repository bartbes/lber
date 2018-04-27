local lber_handle = {}

function lber_handle.fromString(str)
	return
	{
		str = str,
		pos = 1,
	}
end

function lber_handle.toString(handle, full)
	if not full then
		return handle.str:sub(handle.pos)
	else
		return handle.str
	end
end

-- TODO: Explicit bounds checks

function lber_handle.read(handle, count)
	local data = handle.str:sub(handle.pos, handle.pos+count-1)
	handle.pos = handle.pos + #data
	return data
end

function lber_handle.readByte(handle)
	local data = handle.str:byte(handle.pos)
	handle.pos = handle.pos + 1
	return data
end

function lber_handle.peekByte(handle)
	return handle.str:byte(handle.pos)
end

function lber_handle.isEof(handle)
	return handle.pos >= #handle.str
end

return lber_handle
