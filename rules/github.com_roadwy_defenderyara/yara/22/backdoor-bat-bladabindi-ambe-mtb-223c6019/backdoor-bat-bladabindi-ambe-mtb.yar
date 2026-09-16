rule Backdoor_BAT_Bladabindi_AMBE_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 09 11 08 5d 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}