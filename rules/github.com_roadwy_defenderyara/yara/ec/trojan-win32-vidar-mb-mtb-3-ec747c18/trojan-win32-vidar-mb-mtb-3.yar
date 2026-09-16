rule Trojan_Win32_Vidar_MB_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 85 10 fc ff ff 33 d2 f7 f1 8b 85 0c fc ff ff 8a 0c 02 8b 85 10 fc ff ff 8b 95 08 fc ff ff 03 c3 32 0c 02 88 08 8d 85 14 fc ff ff 50 } 		$a_01_1 = {73 64 66 6b 6a 6e 73 64 66 6b 6a 6c 6e 6b 20 6a 68 73 64 62 66 6a 73 68 64 } 		$a_01_2 = {8b c8 8b 85 28 f8 ff ff 33 d2 f7 f1 8b 85 20 f8 ff ff 8a 0c 02 8b 85 18 f8 ff ff 8b 95 1c f8 ff ff 32 0c 02 88 08 8d 85 2c f8 ff ff 50 8d 85 14 fc ff ff 50 } 		$a_01_3 = {73 6b 6a 64 33 38 37 32 36 32 38 37 33 34 36 77 75 79 67 32 33 37 36 34 74 32 67 66 37 36 66 67 79 74 72 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*20+(#a_01_3  & 1)*5) >=25
 
}