rule Trojan_BAT_AgentTesla_AL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 00 11 05 7b 10 00 00 04 28 21 00 00 0a 28 22 00 00 0a 6f 23 00 00 0a 00 dd 05 } 		$a_01_1 = {52 00 46 00 45 00 53 00 58 00 47 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}