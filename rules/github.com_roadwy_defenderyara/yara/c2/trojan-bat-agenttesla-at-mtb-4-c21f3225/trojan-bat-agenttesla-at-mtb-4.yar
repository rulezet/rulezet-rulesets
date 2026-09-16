rule Trojan_BAT_AgentTesla_AT_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 13 06 08 17 8d ?? 00 00 01 25 16 11 06 9c 6f } 		$a_01_1 = {71 75 61 6e 6c 79 63 75 61 68 61 6e 67 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}