rule Trojan_BAT_AgentTesla_NSN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 7b 6b 00 00 04 7e ?? ?? ?? 04 20 ?? ?? ?? 4a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a } 		$a_01_1 = {41 4d 41 5a 49 4e 47 4e 45 57 57 4f 52 4c 44 5f 4c 41 55 4e 43 48 45 52 } 		$a_01_2 = {24 36 64 34 35 33 30 35 61 2d 38 30 31 66 2d 34 63 36 36 2d 38 37 62 37 2d 38 30 66 35 32 33 31 35 38 63 34 61 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}