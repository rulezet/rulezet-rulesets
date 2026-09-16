rule Trojan_BAT_AgentTesla_MBKM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d } 		$a_01_1 = {5a 00 34 00 33 00 5a 00 5a 00 45 00 32 00 5a 00 5a 00 34 00 33 00 5a 00 5a 00 45 00 32 00 5a 00 5a 00 5a 00 33 00 5a 00 5a 00 45 00 32 00 5a 00 5a 00 34 00 33 00 5a 00 5a 00 5a 00 5a } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}