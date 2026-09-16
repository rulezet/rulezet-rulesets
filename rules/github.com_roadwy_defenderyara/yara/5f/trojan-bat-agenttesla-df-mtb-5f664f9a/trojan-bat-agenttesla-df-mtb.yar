rule Trojan_BAT_AgentTesla_DF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 1d 5d 16 fe 01 0d 09 2c 0b 06 08 06 08 91 1f 4b 61 b4 9c 00 00 08 17 d6 0c 08 07 31 } 		$a_01_1 = {52 65 76 65 72 73 65 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}