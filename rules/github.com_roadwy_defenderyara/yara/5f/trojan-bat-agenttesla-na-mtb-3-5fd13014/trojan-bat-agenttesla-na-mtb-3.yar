rule Trojan_BAT_AgentTesla_NA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 6f 2c 00 00 0a 0c 20 ?? ?? ?? ff 28 ?? ?? ?? 0a fe ?? ?? 00 38 ?? ?? ?? 00 } 		$a_01_1 = {70 75 62 6c 69 63 2e 63 6c 61 73 73 2e 4d 61 69 6e 2e 48 65 6c 6c 6f 57 6f 72 6c 64 2e 6d 6f 64 75 6c 65 31 33 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}