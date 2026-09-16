rule Trojan_Win32_Redline_MF_MTB_5{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 83 c2 02 89 55 f8 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb } 		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_01_2 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } 		$a_01_3 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}