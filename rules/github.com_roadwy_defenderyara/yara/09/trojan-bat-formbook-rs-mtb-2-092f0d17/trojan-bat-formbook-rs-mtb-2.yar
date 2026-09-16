rule Trojan_BAT_Formbook_RS_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 06 0b 28 3f 00 00 0a } 		$a_01_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 42 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}