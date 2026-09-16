rule PWS_Win32_QQpass_FP_2{
	meta:
		description = "PWS:Win32/QQpass.FP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 77 77 73 3d 32 32 34 3a 36 31 35 38 35 31 34 3c 37 31 35 37 33 32 7a 68 65 } 		$a_01_1 = {c6 85 04 e4 fd ff 71 c6 85 05 e4 fd ff 71 c6 85 06 e4 fd ff 2e c6 85 07 e4 fd ff 65 c6 85 08 e4 fd ff 78 c6 85 09 e4 fd ff 65 } 		$a_01_2 = {c6 85 fc dc fd ff 5c c6 85 fd dc fd ff 51 c6 85 fe dc fd ff 51 c6 85 ff dc fd ff 5c c6 85 00 dd fd ff 52 c6 85 01 dd fd ff 65 c6 85 02 dd fd ff 67 c6 85 03 dd fd ff 69 c6 85 04 dd fd ff 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}