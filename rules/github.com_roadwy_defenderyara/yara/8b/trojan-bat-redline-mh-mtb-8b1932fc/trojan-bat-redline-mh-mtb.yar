rule Trojan_BAT_RedLine_MH_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 03 16 11 03 8e 69 6f ?? ?? ?? 0a 13 06 38 ?? ?? ?? ?? 14 13 06 20 01 00 00 00 28 ?? ?? ?? 06 3a ?? ?? ?? ?? 26 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}