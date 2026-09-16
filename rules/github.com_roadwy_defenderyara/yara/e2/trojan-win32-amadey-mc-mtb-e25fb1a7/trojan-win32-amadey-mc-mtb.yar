rule Trojan_Win32_Amadey_MC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 66 81 e3 a9 02 c1 c8 6e 66 c1 e9 73 66 03 f8 c1 c2 30 c1 c1 0b 23 c8 66 81 cf 36 02 43 66 be a8 01 66 c1 ca 46 f7 e6 81 ef c8 02 00 00 66 81 e2 5e 02 66 47 0f b6 c0 0f b7 ca 4f c1 e6 30 74 } 		$a_01_1 = {5f 6a 62 78 6a 67 62 67 75 79 77 33 40 34 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}