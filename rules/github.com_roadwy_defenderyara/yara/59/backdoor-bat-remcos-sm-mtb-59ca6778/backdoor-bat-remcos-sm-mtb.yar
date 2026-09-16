rule Backdoor_BAT_Remcos_SM_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 8f 11 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } 		$a_81_1 = {57 4e 48 42 4e 4d 4b 4c 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}