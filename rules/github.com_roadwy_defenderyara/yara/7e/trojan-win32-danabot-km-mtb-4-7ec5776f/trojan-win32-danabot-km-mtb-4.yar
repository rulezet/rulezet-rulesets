rule Trojan_Win32_Danabot_KM_MTB_4{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 08 88 04 0a 59 c3 } 		$a_02_1 = {0f b6 d3 03 ca a3 ?? ?? ?? ?? 81 e1 ff 00 00 00 8a 81 ?? ?? ?? ?? 30 04 37 83 6d ?? 01 8b 75 ?? 85 f6 7d } 	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}