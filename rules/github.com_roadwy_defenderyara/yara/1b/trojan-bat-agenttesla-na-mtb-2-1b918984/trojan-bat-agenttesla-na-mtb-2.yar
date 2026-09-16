rule Trojan_BAT_AgentTesla_NA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 7c 3b 02 70 17 8d ?? ?? ?? 01 25 16 11 01 a2 25 13 02 } 		$a_01_1 = {51 00 51 00 51 00 57 00 57 00 57 00 } 		$a_01_2 = {62 00 6c 00 6e 00 41 00 6f 00 79 00 58 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}