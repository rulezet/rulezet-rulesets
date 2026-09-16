rule Trojan_Win32_Zusy_AZY_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 46 08 89 45 cc 8d 95 68 fe ff ff b8 64 89 4b 00 e8 2f f5 ff ff 8b 95 68 fe ff ff 8b 45 c4 e8 0d c3 f4 ff 75 02 b3 01 8d 95 64 fe ff ff b8 88 89 4b 00 e8 0d f5 ff ff 8b 95 64 fe ff ff 8b 45 c4 e8 eb c2 f4 ff 75 04 c6 45 fb 01 8d 95 60 fe ff ff b8 a4 89 4b 00 e8 e9 f4 ff ff 8b 95 60 fe ff ff 8b 45 c4 e8 c7 c2 f4 ff 75 04 c6 45 fa 01 8d 95 5c fe ff ff b8 c8 89 4b 00 } 		$a_01_1 = {30 31 39 46 39 41 32 37 37 41 35 31 44 45 32 38 35 37 38 37 43 46 33 43 37 37 } 		$a_01_2 = {35 34 43 30 44 38 32 31 37 34 34 43 43 39 36 42 35 37 44 31 43 46 } 		$a_01_3 = {35 31 43 31 44 38 32 42 37 46 34 36 39 46 32 30 34 41 43 43 } 		$a_01_4 = {35 30 43 38 43 33 32 30 36 37 34 31 43 33 32 41 34 35 44 41 43 46 33 36 33 43 34 36 43 39 32 30 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}