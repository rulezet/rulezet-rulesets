rule Trojan_Win32_Zbot_RG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 b4 25 2c ff ff ff 8c 12 00 00 89 b4 25 ?? ff ff ff 8b 32 89 34 87 c1 2d ?? ?? ?? ?? 07 40 3b 45 14 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}