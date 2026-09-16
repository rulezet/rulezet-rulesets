rule Trojan_Win32_Vidar_NV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 c1 20 0f 45 f7 0f 45 f8 89 bc cc 5c 0b 00 00 31 d6 89 b4 cc 58 0b 00 00 f6 c1 0f 75 c5 } 		$a_01_1 = {c1 e6 05 8b bc 24 58 01 00 00 0f b7 9c 4c 58 09 00 00 01 fb 01 f3 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}