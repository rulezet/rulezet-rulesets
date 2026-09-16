rule Ransom_Win32_Spora_B_2{
	meta:
		description = "Ransom:Win32/Spora.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3c 68 74 61 3a 61 70 70 6c 69 63 61 74 69 6f 6e 20 77 69 6e 64 6f 77 73 74 61 74 65 3d 22 6d 69 6e 69 6d 69 7a 65 22 2f 3e 3c 73 63 72 69 70 74 3e 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 28 22 63 6d 64 20 2f 63 20 5c 22 5c 22 22 2b 77 69 6e 64 6f 77 2e 6c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}