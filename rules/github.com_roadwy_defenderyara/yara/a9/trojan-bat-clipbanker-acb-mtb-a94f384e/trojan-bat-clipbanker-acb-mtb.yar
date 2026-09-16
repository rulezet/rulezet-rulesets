rule Trojan_BAT_ClipBanker_ACB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 02 a2 25 18 72 ?? ?? ?? 70 a2 25 19 03 a2 25 1a 72 ?? ?? ?? 70 a2 25 1b 04 a2 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 0b 07 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}