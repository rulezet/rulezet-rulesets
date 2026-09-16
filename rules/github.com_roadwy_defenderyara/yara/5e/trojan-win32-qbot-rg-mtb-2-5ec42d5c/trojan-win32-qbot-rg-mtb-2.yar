rule Trojan_Win32_Qbot_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 25 ff 00 00 00 0f b6 ?? ?? ?? ?? ?? 30 14 37 83 6c 24 ?? 01 8b 74 24 ?? 85 f6 } 		$a_02_1 = {81 e1 ff 00 00 00 8a 91 ?? ?? ?? ?? 0f b6 c2 03 05 ?? ?? ?? ?? 89 0d } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}