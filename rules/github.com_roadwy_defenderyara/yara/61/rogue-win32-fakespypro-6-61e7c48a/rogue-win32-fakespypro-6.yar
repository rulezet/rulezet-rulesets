rule Rogue_Win32_FakeSpypro_6{
	meta:
		description = "Rogue:Win32/FakeSpypro,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe ff ce fe 8d 44 24 0c 50 ff 74 08 07 e8 90 09 20 02 55 50 58 30 00 00 00 00 00 (90 90|a0) 02 00 00 10 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 e0 55 50 58 31 00 00 00 00 00 30 03 00 00 90 03 01 01 a0 b0 02 00 00 ?? 03 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}