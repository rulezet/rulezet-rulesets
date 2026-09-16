rule Trojan_Win32_Zusy_CA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {f7 d7 09 fb 83 e7 [0-04] 09 fe f7 d3 bf [0-04] 31 c6 8b 45 [0-04] 09 f3 88 18 b4 [0-04] b3 [0-04] 2a 65 [0-04] 28 e3 be [0-04] 81 fe } 		$a_03_1 = {31 fe f7 d3 83 f6 [0-04] 89 5d } 		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}