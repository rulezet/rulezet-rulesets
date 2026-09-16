rule Trojan_Win32_Pikabot_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Pikabot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 ed 01 86 9c 00 00 00 0f b6 c2 0f b6 56 68 0f af d0 a1 ?? ?? ?? ?? 88 14 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}