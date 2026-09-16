rule Trojan_Win32_Qakbot_GF_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 d8 81 c1 a8 a1 02 01 89 0d ?? ?? ?? ?? 89 0a 0f b6 cb 66 2b 0d ?? ?? ?? ?? 66 2b ce 66 8b f1 8b ca 8b 15 ?? ?? ?? ?? 83 c1 04 ff 4c 24 ?? 66 89 35 ?? ?? ?? ?? 89 4c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}