rule Backdoor_BAT_Bladabindi_ARAC_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0a 38 ?? ?? ?? ?? 17 11 08 58 13 08 11 08 08 fe 04 } 		$a_01_1 = {35 73 38 73 38 51 76 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}