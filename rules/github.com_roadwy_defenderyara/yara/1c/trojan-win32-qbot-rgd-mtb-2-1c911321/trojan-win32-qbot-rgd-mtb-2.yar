rule Trojan_Win32_Qbot_RGD_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {05 c2 5a 00 00 8b 4d ?? 8b 11 2b d0 8b 45 ?? 89 10 8b e5 5d } 		$a_02_1 = {33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}