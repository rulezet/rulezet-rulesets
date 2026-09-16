rule Trojan_Win32_Antivirusxp_5{
	meta:
		description = "Trojan:Win32/Antivirusxp,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 41 6e 74 69 76 69 72 75 73 20 58 50 20 32 30 30 38 00 } 		$a_01_1 = {2e 65 78 65 00 4b 69 6c 6c 50 72 6f 63 } 		$a_01_2 = {4d 75 74 65 78 2e 64 6c 6c 00 4d 75 74 65 78 43 68 65 63 6b } 		$a_01_3 = {4d 61 63 68 69 6e 65 4b 65 79 2e 64 6c 6c 00 47 65 74 4b 65 79 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}