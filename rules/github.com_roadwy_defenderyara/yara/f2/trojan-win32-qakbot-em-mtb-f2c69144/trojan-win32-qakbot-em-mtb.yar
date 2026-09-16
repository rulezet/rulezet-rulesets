rule Trojan_Win32_Qakbot_EM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 0f b6 4c 05 } 		$a_01_1 = {f7 f6 0f b6 44 15 } 		$a_01_2 = {33 c8 8b 45 } 		$a_01_3 = {88 4c 05 a4 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}