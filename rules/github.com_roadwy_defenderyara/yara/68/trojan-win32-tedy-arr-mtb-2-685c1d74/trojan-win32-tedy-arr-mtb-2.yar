rule Trojan_Win32_Tedy_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 05 00 00 "
		
	strings :
		$a_01_0 = {b0 b3 03 f5 04 00 00 70 f5 b2 03 cc b7 00 } 		$a_01_1 = {3c 2d 3e 02 00 80 75 01 00 2e 3e 02 00 0a } 		$a_01_2 = {b0 b3 03 00 06 00 00 00 38 3e 02 } 		$a_01_3 = {e6 f3 02 00 00 60 10 00 } 		$a_81_4 = {53 74 65 61 6c 65 72 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_81_4  & 1)*20) >=40
 
}