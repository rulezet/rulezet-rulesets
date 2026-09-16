rule Trojan_BAT_AgentTesla_MBV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 07 1f 11 5a 11 07 18 62 61 20 ?? 00 00 00 60 9e 11 07 17 58 13 07 } 		$a_01_1 = {66 34 33 32 36 63 36 65 62 62 34 34 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}