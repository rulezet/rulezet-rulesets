rule Trojan_Win32_Qakbot_AI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 66 30 61 62 32 37 31 37 61 66 39 62 66 65 30 } 		$a_01_1 = {33 61 36 66 37 64 63 30 36 62 37 63 31 62 66 31 } 		$a_01_2 = {35 33 63 64 37 65 37 34 36 39 63 33 33 32 63 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}