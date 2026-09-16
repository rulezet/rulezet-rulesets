rule Backdoor_BAT_Bladabindi_ARAC_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 91 13 07 08 17 58 20 ff 00 00 00 5f 0c 09 06 08 91 58 20 ff 00 00 00 5f 0d 06 08 09 28 0a 00 00 06 07 11 04 11 07 06 06 08 91 06 09 91 58 20 ff 00 00 00 5f 91 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 32 b6 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}