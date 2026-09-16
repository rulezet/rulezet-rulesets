rule is_executable
{
	condition:
		uint16(0) == 0x5A4D or uint32(0) == 0x464c457f or uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}