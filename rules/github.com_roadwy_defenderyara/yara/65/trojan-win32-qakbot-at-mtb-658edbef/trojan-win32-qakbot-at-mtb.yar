rule Trojan_Win32_Qakbot_AT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 31 39 37 66 32 61 64 64 64 34 38 32 66 37 30 } 		$a_01_1 = {38 37 30 65 65 38 32 66 63 62 39 30 30 32 62 66 } 		$a_01_2 = {37 63 65 31 32 64 38 61 31 30 66 34 63 34 39 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}