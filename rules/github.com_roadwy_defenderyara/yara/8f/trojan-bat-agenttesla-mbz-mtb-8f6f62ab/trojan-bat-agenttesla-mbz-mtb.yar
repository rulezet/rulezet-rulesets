rule Trojan_BAT_AgentTesla_MBZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 06 93 0b 06 18 58 93 07 61 0b 11 0f 20 ?? 00 00 00 93 } 		$a_01_1 = {33 66 34 32 66 36 63 31 37 35 63 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}