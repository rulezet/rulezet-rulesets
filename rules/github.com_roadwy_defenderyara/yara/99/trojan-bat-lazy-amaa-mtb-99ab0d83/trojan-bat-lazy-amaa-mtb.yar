rule Trojan_BAT_Lazy_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 07 91 66 d2 9c 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 07 17 58 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}