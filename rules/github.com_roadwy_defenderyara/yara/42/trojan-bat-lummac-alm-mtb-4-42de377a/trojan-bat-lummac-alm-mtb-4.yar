rule Trojan_BAT_LummaC_ALM_MTB_4{
	meta:
		description = "Trojan:BAT/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 08 17 58 } 		$a_01_1 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1c 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}