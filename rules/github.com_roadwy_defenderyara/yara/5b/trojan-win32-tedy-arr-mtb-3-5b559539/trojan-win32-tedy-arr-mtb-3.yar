rule Trojan_Win32_Tedy_ARR_MTB_3{
	meta:
		description = "Trojan:Win32/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 30 36 39 65 37 64 62 61 2d 33 62 36 38 2d 34 35 62 34 2d 61 38 37 33 2d 34 32 34 38 37 33 37 30 63 62 32 65 } 		$a_81_1 = {53 74 65 61 6c 31 2e 65 78 65 } 		$a_81_2 = {53 74 65 61 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*15+(#a_81_2  & 1)*5) >=30
 
}