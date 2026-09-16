rule Rogue_Win32_FakeScanti_3{
	meta:
		description = "Rogue:Win32/FakeScanti,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {12 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 50 00 6f 00 6c 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 12 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 32 00 30 00 30 00 39 00 20 00 50 00 72 00 6f 00 ?? 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}