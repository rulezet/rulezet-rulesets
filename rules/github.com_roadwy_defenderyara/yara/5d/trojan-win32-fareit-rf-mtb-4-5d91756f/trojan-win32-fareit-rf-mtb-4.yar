rule Trojan_Win32_Fareit_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {81 34 07 7c b1 6a 45 66 83 c0 00 f3 0f 7e ec 66 0f 6e d9 66 0f } 		$a_01_1 = {46 6f 6c 6b 65 62 69 62 6c 69 6f 74 65 6b 65 72 6e 65 32 } 		$a_01_2 = {53 75 70 65 72 72 69 67 68 74 65 6f 75 73 6c 79 36 } 		$a_01_3 = {54 65 6b 6e 6f 6c 6f 67 69 76 75 72 64 65 72 69 6e 67 73 70 72 6f 6a 65 6b 74 65 74 39 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}