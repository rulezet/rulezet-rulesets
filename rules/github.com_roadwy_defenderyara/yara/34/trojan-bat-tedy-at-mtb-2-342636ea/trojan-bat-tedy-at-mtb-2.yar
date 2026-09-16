rule Trojan_BAT_Tedy_AT_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 06 91 1f 48 33 1d 03 06 17 58 91 1f 43 33 14 03 06 18 58 91 1f 46 33 0b 03 06 19 58 91 1f 47 33 02 06 2a 06 1a 59 0a 06 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}