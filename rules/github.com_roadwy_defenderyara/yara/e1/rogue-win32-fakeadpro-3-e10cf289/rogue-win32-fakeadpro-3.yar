rule Rogue_Win32_FakeAdpro_3{
	meta:
		description = "Rogue:Win32/FakeAdpro,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {45 6e 67 69 6e 65 41 50 2e 64 6c 6c [0-10] 45 6e 67 69 6e 65 20 66 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 2e 20 45 72 72 6f 72 3a 25 64 90 0a f0 00 53 65 6e 64 4c 6f 67 [0-10] 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-50] 47 6c 6f 62 61 6c 5c [0-22] 53 6f 66 74 77 61 72 65 5c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}