rule Trojan_BAT_RedLineStealer_AD_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 10 2b 15 28 ?? ?? ?? ?? 2b f1 28 ?? ?? ?? ?? 2b ed 28 ?? ?? ?? ?? 2b 00 2a } 		$a_01_1 = {66 30 36 35 39 65 35 39 30 35 34 35 34 61 35 65 39 39 62 39 37 35 32 61 66 63 37 38 62 37 30 30 00 } 		$a_03_2 = {00 70 14 1e 2d 06 26 26 26 26 2b 07 90 0a 2f 00 28 ?? ?? 00 06 28 ?? ?? 00 06 72 ?? ?? 00 70 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}