rule Trojan_BAT_Lazy_PGL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 1f 14 6f ?? 00 00 0a 13 04 2b 29 11 04 1f 0a fe 02 13 06 11 06 2c 0c 07 08 66 5f 07 66 08 5f 60 0d 2b 16 11 05 74 ?? 00 00 01 17 1f 14 6f ?? 00 00 0a 13 04 17 13 07 2b d2 09 28 ?? 00 00 0a 0a 06 2a } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}