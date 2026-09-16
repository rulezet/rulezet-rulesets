rule Trojan_Win32_Zusy_ARR_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 43 da 33 06 4d 6c 3c 45 } 		$a_03_1 = {dc 36 02 ec 98 6b c1 ?? ee d3 ce 32 4a fc } 		$a_01_2 = {33 3c 24 31 3c 24 33 3c 24 5c 8d 44 24 24 } 		$a_03_3 = {67 32 15 66 e7 ?? ?? ?? d6 ed 53 ab } 	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*5+(#a_01_2  & 1)*15+(#a_03_3  & 1)*5) >=20
 
}