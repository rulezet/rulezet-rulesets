rule Trojan_Win32_Fareit_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {40 2a 5c 41 50 72 6f 6a 65 63 74 31 } 		$a_81_1 = {31 38 35 2e 37 2e 32 31 34 2e 37 2f 41 44 53 31 31 2f 52 45 44 2e 50 4e 47 } 		$a_81_2 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 65 72 2e 6f 72 67 2f 31 70 75 63 75 37 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}