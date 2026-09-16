rule Rogue_Win32_FakeSpypro_20{
	meta:
		description = "Rogue:Win32/FakeSpypro,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 4e 5f 87 2a c7 04 24 94 fe 63 50 48 f5 68 73 17 f5 00 68 47 ce f2 d1 83 f8 00 60 66 89 7c 24 04 68 35 d3 81 53 68 a6 2d d7 02 8d 64 24 34 0f 85 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}