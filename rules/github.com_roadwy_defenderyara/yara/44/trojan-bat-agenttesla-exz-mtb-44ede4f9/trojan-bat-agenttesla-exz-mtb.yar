rule Trojan_BAT_AgentTesla_EXZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 20 00 b4 00 00 5d 07 06 20 00 b4 00 00 5d 91 09 06 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 06 17 58 20 00 b4 00 00 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 d2 9c } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}