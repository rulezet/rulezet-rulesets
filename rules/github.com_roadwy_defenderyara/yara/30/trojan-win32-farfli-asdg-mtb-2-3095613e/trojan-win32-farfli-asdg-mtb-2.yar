rule Trojan_Win32_Farfli_ASDG_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ASDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d6 8b 55 fc 8b 45 f8 0f b6 0c 17 0f b6 04 10 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 0f b6 04 11 30 83 [0-04] 43 8b 4d f8 81 fb 1c 06 00 00 0f 82 } 		$a_01_1 = {8a 0a 32 4d ef 02 4d ef 88 0a c3 8b 45 e4 ff 45 e8 40 c7 45 fc 01 00 00 00 eb } 		$a_01_2 = {46 75 63 6b } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}