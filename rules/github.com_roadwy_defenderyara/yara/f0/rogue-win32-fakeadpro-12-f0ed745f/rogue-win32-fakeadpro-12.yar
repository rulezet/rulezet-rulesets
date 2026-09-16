rule Rogue_Win32_FakeAdpro_12{
	meta:
		description = "Rogue:Win32/FakeAdpro,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 45 6e 67 69 6e 65 41 50 2e 64 6c 6c 00 43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00 52 65 6c 65 61 73 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00 } 		$a_01_1 = {5c 52 65 6c 65 61 73 65 5c 53 53 45 6e 67 69 6e 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}