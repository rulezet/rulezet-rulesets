rule Trojan_Win32_AgentTesla_BA_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 40 89 45 f8 81 7d f8 ?? ?? 00 00 73 2d 8b 45 f8 33 d2 6a 3b 59 f7 f1 8b 85 ?? ?? ff ff 0f be 04 10 8b 4d f8 0f b6 8c 0d ?? ?? ff ff 33 c8 8b 45 f8 88 8c 05 ?? ?? ff ff eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}