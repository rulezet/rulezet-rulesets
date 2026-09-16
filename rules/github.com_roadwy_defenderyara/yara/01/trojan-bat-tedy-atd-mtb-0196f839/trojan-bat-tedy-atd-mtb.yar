rule Trojan_BAT_Tedy_ATD_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 1f 0c 13 07 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}