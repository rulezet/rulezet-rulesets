rule Trojan_Win32_Qakbot_DG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 e8 } 		$a_03_1 = {8b d8 8b 45 d8 83 c0 04 03 45 a4 03 d8 e8 [0-04] 2b d8 e8 [0-04] 2b d8 e8 [0-04] 03 d8 89 5d d8 8b 45 a8 3b 45 cc 0f 82 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}