rule IsPE32 : PECheck
{
	condition:
				uint16(0) == 0x5A4D and
				uint16(uint32(0x3C)+0x18) == 0x010B
}