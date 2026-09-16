rule PWS_Win32_Qakbot_MFP_MTB_2{
	meta:
		description = "PWS:Win32/Qakbot.MFP!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 c4 92 20 00 00 c7 45 c0 80 19 00 00 } 		$a_01_1 = {c7 45 e0 90 b9 03 00 c7 45 dc ad 08 00 00 c7 45 d8 7b 00 00 00 c7 45 d4 02 00 00 00 } 		$a_01_2 = {89 45 ec c7 45 b0 8a a5 08 00 8b 45 ec 3b 45 e4 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}