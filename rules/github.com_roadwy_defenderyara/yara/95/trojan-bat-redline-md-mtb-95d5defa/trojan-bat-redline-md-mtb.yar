rule Trojan_BAT_RedLine_MD_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 1b 59 8d ?? 00 00 01 0b 02 1b 07 16 02 8e 69 1b 59 28 ?? 00 00 0a 00 07 16 14 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}