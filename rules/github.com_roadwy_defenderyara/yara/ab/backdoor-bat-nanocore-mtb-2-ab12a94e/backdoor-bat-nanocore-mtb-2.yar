rule Backdoor_BAT_Nanocore_MTB_2{
	meta:
		description = "Backdoor:BAT/Nanocore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {28 82 00 00 0a 00 16 28 83 00 00 0a 00 28 84 00 00 0a 28 08 00 00 06 6f 85 00 00 0a 0a 06 72 ?? 07 00 70 6f 86 00 00 0a 0b 07 72 ?? 08 00 70 6f 87 00 00 0a 0c 07 28 88 00 00 0a 0d 73 32 00 00 06 13 04 1f 09 8d 38 00 00 01 25 } 		$a_02_1 = {28 89 00 00 0a 13 05 08 14 72 ?? 08 00 70 18 8d 14 00 00 01 25 16 09 a2 25 17 17 8d 14 00 00 01 25 16 11 05 a2 a2 14 14 28 8a 00 00 0a 00 2a } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}