rule Trojan_Win32_Trickbot_BS_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 16 8d 84 3d ?? ?? ?? ?? 0f b6 d3 88 18 0f b6 06 03 c2 8b f1 99 f7 fe 8b 45 14 8a 94 15 ?? ?? ?? ?? 30 10 40 ff 4d 0c 89 45 14 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}