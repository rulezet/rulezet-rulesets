rule Backdoor_BAT_Remcos_SMK_MTB_2{
	meta:
		description = "Backdoor:BAT/Remcos.SMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 12 02 28 7f 00 00 0a 6f 80 00 00 0a 03 12 02 28 81 00 00 0a 6f 80 00 00 0a 03 12 02 28 82 00 00 0a 6f 80 00 00 0a 2b 0b 03 6f 83 00 00 0a 19 58 04 31 cc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}