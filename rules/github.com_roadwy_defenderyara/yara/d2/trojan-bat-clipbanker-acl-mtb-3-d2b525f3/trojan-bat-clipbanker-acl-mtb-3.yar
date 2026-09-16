rule Trojan_BAT_ClipBanker_ACL_MTB_3{
	meta:
		description = "Trojan:BAT/ClipBanker.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 1f 64 28 28 00 00 0a 28 27 00 00 0a 07 28 29 00 00 0a 0c 12 02 28 } 		$a_03_1 = {72 db 00 00 70 6f ?? 00 00 0a 25 72 eb 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}