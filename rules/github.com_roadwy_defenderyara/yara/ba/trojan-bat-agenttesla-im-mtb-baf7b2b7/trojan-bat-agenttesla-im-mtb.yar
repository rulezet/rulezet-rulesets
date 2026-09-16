rule Trojan_BAT_AgentTesla_IM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {00 01 25 16 02 03 74 ?? ?? ?? 1b 0b 12 01 28 b2 00 00 06 0c 07 10 01 08 a2 14 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0a 02 06 72 } 		$a_81_1 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } 		$a_81_2 = {69 6d 69 6d 69 6d 69 6d 69 6d } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}