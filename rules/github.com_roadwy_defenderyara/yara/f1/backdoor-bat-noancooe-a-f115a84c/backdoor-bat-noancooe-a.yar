rule Backdoor_BAT_Noancooe_A{
	meta:
		description = "Backdoor:BAT/Noancooe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e } 		$a_03_1 = {1f 1d 12 00 1a 28 ?? 00 00 06 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}