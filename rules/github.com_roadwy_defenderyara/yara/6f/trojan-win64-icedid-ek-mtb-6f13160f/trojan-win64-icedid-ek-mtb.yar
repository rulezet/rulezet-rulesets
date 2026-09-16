rule Trojan_Win64_Icedid_EK_MTB{
	meta:
		description = "Trojan:Win64/Icedid.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 8b 4c 24 04 eb } 		$a_01_1 = {33 c8 8b c1 eb } 		$a_01_2 = {48 63 0c 24 48 8b 94 24 80 00 00 00 e9 } 		$a_01_3 = {88 04 0a e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}