rule Trojan_BAT_AgentTesla_MFP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {20 00 01 00 00 14 14 17 8d ?? ?? ?? 01 25 16 06 a2 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 14 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 07 a2 25 0c 14 14 17 8d ?? ?? ?? 01 25 16 17 9c 25 0d 28 ?? ?? ?? 0a 09 16 91 2c ?? 08 } 		$a_81_1 = {6d 61 69 6c 74 6f 3a 6c 75 75 6e 67 6f 63 32 30 30 35 40 79 61 68 6f 6f 2e 63 6f 6d } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}