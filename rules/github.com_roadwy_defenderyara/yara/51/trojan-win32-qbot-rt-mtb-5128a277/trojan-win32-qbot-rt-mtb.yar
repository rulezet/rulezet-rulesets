rule Trojan_Win32_Qbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d a2 d1 00 00 03 } 		$a_03_1 = {31 02 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 01 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}