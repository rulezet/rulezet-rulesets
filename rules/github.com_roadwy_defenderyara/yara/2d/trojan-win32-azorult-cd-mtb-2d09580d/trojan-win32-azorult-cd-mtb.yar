rule Trojan_Win32_Azorult_CD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 8c 01 3b 2d 0b 00 8b 15 [0-04] 88 0c 02 8b 15 [0-04] 40 3b c2 72 df } 		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}