rule Trojan_Win32_Zusy_ARR_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {87 2c 24 5c 89 14 24 57 89 0c 24 8b 14 24 83 ec } 		$a_01_1 = {47 30 16 b0 83 41 5d } 		$a_03_2 = {ab 3b cd 5b c7 30 dd 65 c0 72 ?? ?? 4c 11 b4 59 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*7+(#a_03_2  & 1)*3) >=20
 
}