rule Backdoor_BAT_Remcos_STK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.STK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 08 18 6f 07 00 00 0a 1f 10 28 08 00 00 0a 6f 09 00 00 0a 08 18 58 0c 08 07 6f 0a 00 00 0a 3f db ff ff ff } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}