rule Trojan_Win32_Tedy_ARR_MTB{
	meta:
		description = "Trojan:Win32/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 46 8a 04 3a 32 04 0b 88 03 8b 5d ec } 		$a_03_1 = {8b 45 f4 8b 4d f8 89 1e 5b 89 46 ?? 8b c6 5f 89 4e } 		$a_81_2 = {51 00 51 00 50 00 43 00 52 00 74 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10+(#a_81_2  & 1)*5) >=30
 
}