rule Trojan_BAT_Tedy_ND_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 06 11 0e 06 8e 69 5d 91 61 d2 52 11 0e 17 58 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}