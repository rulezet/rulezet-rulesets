rule Trojan_Win32_Trickbot_EG_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2b c1 83 c4 48 8b d0 c1 e2 05 2b d0 03 d6 ff } 		$a_02_1 = {57 0f af 35 ?? ?? ?? ?? 8b f9 8b c1 c1 e7 05 2b f9 2b c6 c1 e7 03 8b d0 8b df 8b 7c ?? ?? c1 e2 06 8b 54 ?? ?? 2b d3 8d 1c ?? 8d 2c ?? 8b 5c 3a ?? 03 dd } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}