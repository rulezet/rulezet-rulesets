rule Trojan_Win32_Emotet_SK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 23 77 77 23 50 23 23 23 23 23 23 23 77 4f } 		$a_81_1 = {59 55 51 39 46 2a 6d 69 4f 71 } 		$a_81_2 = {36 21 68 40 4a 30 56 69 23 4f } 		$a_81_3 = {6e 69 37 3d 38 68 4c 4f 36 6f } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}