rule Trojan_BAT_AgentTesla_NAA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5a 28 ?? 00 00 0a 0c 16 0d 06 6f ?? 00 00 0a 07 08 12 03 28 ?? 00 00 06 26 09 76 6c d0 ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6c 5b 28 ?? 00 00 0a } 		$a_01_1 = {31 64 32 61 61 30 61 36 2d 32 63 34 62 2d 34 33 36 39 2d 61 66 31 39 2d 65 66 30 33 65 34 33 63 62 64 37 38 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}