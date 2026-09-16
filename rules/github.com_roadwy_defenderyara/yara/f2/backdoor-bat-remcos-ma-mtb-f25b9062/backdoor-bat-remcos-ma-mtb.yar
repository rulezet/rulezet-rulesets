rule Backdoor_BAT_Remcos_MA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 16 06 8e 69 28 ?? ?? ?? 0a 06 0b dd 03 00 00 00 26 de db } 		$a_01_1 = {3a 00 2f 00 2f 00 62 00 72 00 69 00 61 00 6e 00 65 00 74 00 61 00 76 00 65 00 72 00 61 00 73 00 2e 00 62 00 79 00 65 00 74 00 68 00 6f 00 73 00 74 00 31 00 33 00 2e 00 63 00 6f 00 6d 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}