rule Backdoor_BAT_Remcos_SUK_MTB_2{
	meta:
		description = "Backdoor:BAT/Remcos.SUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 17 59 25 0d 16 fe 02 16 fe 01 13 0a 11 0a 2c 02 2b 41 03 12 0c 28 6c 00 00 0a 6f 51 00 00 0a 09 17 59 25 0d 16 fe 02 16 fe 01 13 0b 11 0b 2c 02 } 		$a_81_1 = {43 79 63 6c 65 5f 4a 75 6d 70 5f 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}