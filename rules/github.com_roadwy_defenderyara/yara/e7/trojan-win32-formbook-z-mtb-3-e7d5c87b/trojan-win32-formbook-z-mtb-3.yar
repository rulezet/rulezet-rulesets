rule Trojan_Win32_FormBook_Z_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 0a 00 00 "
		
	strings :
		$a_01_0 = {03 c8 0f 31 2b c1 89 45 fc } 		$a_01_1 = {3c 24 0f 84 76 ff ff ff 3c 25 74 94 } 		$a_01_2 = {3b 4f 14 73 95 85 c9 74 91 } 		$a_01_3 = {3c 69 75 44 8b 7d 18 8b 0f } 		$a_01_4 = {5d c3 8d 50 7c 80 fa 07 } 		$a_01_5 = {0f be 5c 0e 01 0f b6 54 0e 02 83 e3 0f c1 ea 06 } 		$a_01_6 = {57 89 45 fc 89 45 f4 89 45 f8 } 		$a_01_7 = {66 89 0c 02 5b 8b e5 5d } 		$a_01_8 = {3c 54 74 04 3c 74 75 f4 } 		$a_01_9 = {56 68 03 01 00 00 8d 85 95 fe ff ff 6a 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=2
 
}