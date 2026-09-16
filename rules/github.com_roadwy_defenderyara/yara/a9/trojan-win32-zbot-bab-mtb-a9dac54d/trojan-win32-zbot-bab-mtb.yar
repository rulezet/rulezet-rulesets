rule Trojan_Win32_Zbot_BAB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c2 08 07 8b 45 ?? 0f b6 10 23 15 ?? ?? ?? ?? 8b c3 2b c2 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}