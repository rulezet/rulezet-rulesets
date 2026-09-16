rule Trojan_BAT_PureCrypter_ARAX_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 12 02 28 ?? ?? ?? 0a 13 06 12 02 28 ?? ?? ?? 0a 13 07 03 11 05 16 61 d2 6f ?? ?? ?? 0a 00 03 11 06 16 61 d2 6f ?? ?? ?? 0a 00 03 11 07 16 61 d2 6f ?? ?? ?? 0a 00 2b 15 03 6f ?? ?? ?? 0a 19 58 04 31 03 16 2b 01 17 13 08 11 08 2d a9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}