rule Trojan_BAT_ClipBanker_ACL_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 dc 05 00 00 28 ?? 00 00 0a 17 72 ?? 13 00 70 12 00 73 ?? 00 00 0a 80 ?? 00 00 04 06 2d 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}