rule Trojan_BAT_AgentTesla_NA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 25 1a 58 13 07 4b 11 07 25 1a 58 13 07 4b 5a 13 11 11 11 20 ?? ?? ?? dc 33 2d 08 07 2d 07 } 		$a_01_1 = {4d 4b 4d 4e 6e 4e 39 38 38 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}