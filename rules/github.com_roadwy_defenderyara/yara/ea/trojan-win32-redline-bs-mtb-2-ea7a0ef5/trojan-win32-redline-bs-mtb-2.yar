rule Trojan_Win32_RedLine_BS_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 85 f4 fb ff ff 0f b6 00 8b 8d e4 f7 ff ff 33 84 8d f8 fb ff ff 8b 8d f0 fb ff ff 03 8d f4 fb ff ff 88 01 e9 } 		$a_01_1 = {45 78 6f 64 75 73 20 57 65 62 33 20 57 61 6c 6c 65 74 } 		$a_01_2 = {4b 65 65 50 61 73 73 20 54 75 73 6b } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}