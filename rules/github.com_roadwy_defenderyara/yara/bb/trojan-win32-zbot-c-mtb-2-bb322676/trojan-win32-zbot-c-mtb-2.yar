rule Trojan_Win32_Zbot_C_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f1 8b 0d ?? ?? ?? ?? 83 c1 52 8b 85 38 fc ff ff 33 d2 f7 f1 0f af 05 ?? ?? ?? ?? 2b f0 89 b5 48 fc ff ff 0f b6 95 0f fc ff ff 33 95 08 fc ff ff 88 95 07 fc ff ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}