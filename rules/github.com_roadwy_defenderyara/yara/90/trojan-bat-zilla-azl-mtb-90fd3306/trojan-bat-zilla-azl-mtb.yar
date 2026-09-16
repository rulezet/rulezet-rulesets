rule Trojan_BAT_Zilla_AZL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 16 0c 2b 74 20 f4 01 00 00 28 ?? 00 00 0a 12 03 fe 15 ?? 00 00 02 12 03 28 ?? 00 00 06 2d 0e 03 72 ?? 17 00 70 6f ?? 00 00 0a 26 2b 47 09 7b ?? 00 00 04 07 7b ?? 00 00 04 33 0e 09 7b ?? 00 00 04 07 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}