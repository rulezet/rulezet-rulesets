rule Trojan_BAT_Bladabindi_ABD_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 0d 00 00 04 a2 11 12 18 28 ?? ?? ?? 0a 13 0f 12 0f 28 ?? ?? ?? 06 a2 11 12 19 7e 0d 00 00 04 a2 11 12 1a 7e 0e 00 00 04 13 10 12 10 28 ?? ?? ?? 06 a2 11 12 1b } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}