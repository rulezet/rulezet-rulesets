rule Trojan_Win32_Qakbot_PT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 c3 33 c0 c3 33 c0 c3 } 		$a_03_1 = {8b d1 c7 45 [0-06] 66 c7 45 [0-06] 8a 44 15 ?? 34 ab 88 44 15 ?? 42 83 fa ?? 7c ?? 88 4d } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}