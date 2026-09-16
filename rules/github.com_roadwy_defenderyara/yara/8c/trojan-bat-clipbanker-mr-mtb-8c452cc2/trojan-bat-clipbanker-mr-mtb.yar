rule Trojan_BAT_ClipBanker_MR_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 3a 5a 11 06 58 13 08 07 11 07 11 08 20 ff ?? ?? ?? 5f d2 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}