rule Trojan_Win32_Qakbot_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 61 64 37 35 65 33 30 30 32 38 31 32 33 31 65 } 		$a_01_1 = {34 66 31 38 39 32 34 38 33 39 62 63 39 65 63 30 } 		$a_01_2 = {61 30 37 38 38 65 61 62 64 31 36 66 36 34 39 37 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}