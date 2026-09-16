rule Trojan_Win32_Qakbot_GI_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 [0-08] 2b d8 8b 45 ?? 31 18 } 		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } 		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}