rule Trojan_Win32_Redline_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 f6 83 ec 18 c7 04 24 00 00 00 00 c7 44 24 04 00 00 00 00 89 54 24 08 89 4c 24 0c c7 44 24 10 00 00 00 00 c7 44 24 14 00 00 00 00 ff d0 89 c1 } 		$a_01_1 = {31 f6 83 ee 01 89 c2 01 f2 0f af c2 83 e0 01 83 f8 00 0f 94 c0 83 f9 0a 0f 9c c1 88 c2 20 ca 30 c8 08 c2 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}