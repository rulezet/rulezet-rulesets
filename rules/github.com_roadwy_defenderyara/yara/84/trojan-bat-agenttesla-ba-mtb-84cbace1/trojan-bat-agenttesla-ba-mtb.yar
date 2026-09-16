rule Trojan_BAT_AgentTesla_BA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 50 06 02 50 8e b7 6a 5d b7 02 50 06 02 50 8e b7 6a 5d b7 91 03 06 03 8e b7 6a 5d b7 91 61 02 50 06 17 6a d6 02 50 8e b7 6a 5d b7 91 da 20 ?? ?? ?? ?? d6 20 ?? ?? ?? ?? 5d b4 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}