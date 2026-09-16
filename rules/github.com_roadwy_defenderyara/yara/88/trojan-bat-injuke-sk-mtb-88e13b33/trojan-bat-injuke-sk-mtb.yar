rule Trojan_BAT_Injuke_SK_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 11 0d 58 13 05 00 11 0d 17 58 13 0d 11 0d 1f 0a fe 04 13 0e 11 0e 2d e5 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}