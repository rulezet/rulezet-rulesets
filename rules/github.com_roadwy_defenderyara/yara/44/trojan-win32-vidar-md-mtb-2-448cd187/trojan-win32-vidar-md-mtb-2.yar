rule Trojan_Win32_Vidar_MD_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b c6 8b f8 33 d2 8b c1 f7 f7 8b 45 0c 8d 34 19 41 8a 14 02 8b 85 ec fd ff ff 32 14 30 88 16 3b 8d f0 fd ff ff 72 } 		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } 		$a_01_2 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 57 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}