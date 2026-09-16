rule Trojan_BAT_Injuke_AI_MTB_3{
	meta:
		description = "Trojan:BAT/Injuke.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 16 04 a2 09 17 72 01 00 00 70 a2 09 18 28 ?? ?? ?? 0a a2 09 19 72 01 00 00 70 a2 09 1a 7e 11 00 00 04 a2 09 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 0c 06 08 6f ?? ?? ?? 0a 26 06 18 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}