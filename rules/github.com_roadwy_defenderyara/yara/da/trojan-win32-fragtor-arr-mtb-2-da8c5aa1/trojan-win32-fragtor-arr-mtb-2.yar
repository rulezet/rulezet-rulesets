rule Trojan_Win32_Fragtor_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 06 30 14 39 47 3b 7d 0c 72 } 		$a_81_1 = {72 4a 68 37 36 64 41 64 35 5a 59 68 4e 51 74 38 37 5a 51 56 45 76 41 77 } 		$a_81_2 = {73 64 73 64 70 6c 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*8+(#a_81_2  & 1)*2) >=20
 
}