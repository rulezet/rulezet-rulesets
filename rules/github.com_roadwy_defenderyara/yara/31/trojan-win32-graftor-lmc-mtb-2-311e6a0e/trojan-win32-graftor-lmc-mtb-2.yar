rule Trojan_Win32_Graftor_LMC_MTB_2{
	meta:
		description = "Trojan:Win32/Graftor.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 95 3b ff ff ff 33 55 8c 89 55 dc 8b 85 dc fe ff ff 83 e8 45 83 c8 02 88 45 d7 0f b6 8d f3 fe ff ff 2b 8d 14 ff ff ff 81 f1 98 00 00 00 33 0d ?? ?? ?? ?? 88 8d f3 fe ff ff 0f b7 95 d0 fe ff ff 8b 45 b4 } 		$a_01_1 = {8b 4d e8 83 e9 4f 83 f1 15 66 89 8d c8 fe ff ff 8b 95 10 ff ff ff 2b 95 94 fe ff ff 83 e2 5b 89 95 50 ff ff ff 8b 85 a4 fe ff ff 83 c0 01 89 85 08 ff ff ff 8b 4d 8c 83 e1 21 8b 95 d8 fe ff ff 83 ea 18 33 ca 83 f1 35 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}