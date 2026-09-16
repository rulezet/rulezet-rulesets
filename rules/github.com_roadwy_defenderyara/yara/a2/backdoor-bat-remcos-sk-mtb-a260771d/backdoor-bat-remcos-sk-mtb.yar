rule Backdoor_BAT_Remcos_SK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 73 01 00 00 0a 72 01 00 00 70 28 ?? ?? ?? 0a 0a 06 16 06 8e 69 28 ?? ?? ?? 0a 06 0b dd 03 00 00 00 26 de db } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}