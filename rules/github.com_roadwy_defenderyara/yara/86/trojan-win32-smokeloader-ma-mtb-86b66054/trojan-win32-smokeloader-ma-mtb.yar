rule Trojan_Win32_SmokeLoader_MA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ff 8b d0 c1 ea 05 03 54 24 30 8b c8 c1 e1 04 89 54 24 1c 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d 68 73 7b 00 8b 44 24 1c 01 05 68 73 7b 00 } 		$a_01_1 = {8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 89 4c 24 1c 8b 44 24 1c 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 c3 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}