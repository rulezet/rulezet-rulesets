rule anti_debug__ProcDump_PE_Header_Corruption__8_byt_35_
{
strings:
	$a0 = { bb3c0040008b0b81c10600400033db668b195181c1f2000000ba28000000c60100414a }

condition:
	$a0
}