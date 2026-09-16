rule Trojan_BAT_Lazy_ALZ_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 03 1f 10 28 ?? 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 0c 20 00 00 00 00 38 58 00 00 00 00 38 64 01 00 00 00 73 02 01 00 0a 25 11 04 28 ?? 03 00 06 00 25 17 28 ?? 03 00 06 00 25 18 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}