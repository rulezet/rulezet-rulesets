rule Trojan_Win32_Qakbot_MG_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_01_0 = {d9 fc 7a 65 d8 ba 08 00 3d bb 08 00 3d ee 66 6d dc ca 5e 69 d8 cb 47 66 83 d2 64 65 3d bb 08 } 		$a_01_1 = {19 de 40 61 13 df 64 65 f2 ba 08 00 fe c8 6d 61 11 de 4e 69 11 de 49 00 3d bb 08 00 3d bb 08 53 e0 ce 4e 69 d1 dd 58 6f e4 d4 7c 65 cf ba 08 } 		$a_01_2 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } 		$a_01_3 = {47 65 74 54 68 72 65 61 64 4c 6f 63 61 6c 65 } 		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=26
 
}