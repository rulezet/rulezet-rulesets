rule PWS_Win32_QQpass_FP{
	meta:
		description = "PWS:Win32/QQpass.FP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 a4 26 c6 45 a5 71 c6 45 a6 71 c6 45 a7 70 c6 45 a8 61 c6 45 a9 73 c6 45 aa 73 c6 45 ab 77 c6 45 ac 6f c6 45 ad 72 c6 45 ae 64 c6 45 af 3d 88 5d b0 ff d7 } 		$a_03_1 = {80 ea 03 88 94 05 98 fb ff ff 40 3b c7 7e eb 90 09 06 00 8a 90 90 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}