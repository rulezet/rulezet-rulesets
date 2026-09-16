rule Trojan_BAT_Tedy_ATD_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 25 17 28 13 00 00 0a a2 25 18 72 e5 00 00 70 a2 25 19 28 14 00 00 0a a2 25 1a 72 fb 00 00 70 a2 25 1b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}