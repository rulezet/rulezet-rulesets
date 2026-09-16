rule Trojan_Win32_CryptInject_CB_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b c3 8b d3 83 e0 03 c1 ea 02 43 8d 3c 82 8b 54 96 18 8d 0c c5 00 00 00 00 b8 ff 00 00 00 d3 e0 23 d0 d3 ea 30 14 37 83 fb 10 7c d4 } 		$a_00_1 = {32 c0 32 5d ea 32 5d eb 32 d8 8a 46 f8 88 5f fc 84 c0 74 26 } 		$a_00_2 = {8b c2 8b ca c1 e8 02 83 e1 03 03 c6 8a 04 88 88 04 17 42 83 fa 10 72 e8 } 		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}