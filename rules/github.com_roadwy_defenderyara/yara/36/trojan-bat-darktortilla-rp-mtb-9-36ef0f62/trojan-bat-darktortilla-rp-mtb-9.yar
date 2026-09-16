rule Trojan_BAT_DarkTortilla_RP_MTB_9{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 1e 06 19 d8 0a 06 1f 18 fe 02 0c 08 2c 0f 1f 18 0a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 00 00 00 06 1f 18 5d 16 fe ?? 0d 09 ?? d7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}