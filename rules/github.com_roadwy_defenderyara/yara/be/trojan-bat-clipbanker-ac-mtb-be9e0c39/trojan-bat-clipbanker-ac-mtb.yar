rule Trojan_BAT_ClipBanker_AC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 1f 23 28 ?? ?? ?? 0a 72 35 00 00 70 28 ?? ?? ?? 0a 13 05 11 05 18 18 73 08 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}