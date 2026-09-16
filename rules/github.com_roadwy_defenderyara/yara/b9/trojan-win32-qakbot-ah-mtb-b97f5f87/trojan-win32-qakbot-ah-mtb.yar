rule Trojan_Win32_Qakbot_AH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 b5 16 80 45 b5 56 66 3b ed 74 } 		$a_01_1 = {c6 45 b4 3a 80 45 b4 0a e9 } 		$a_01_2 = {c6 45 c2 54 80 45 c2 22 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}