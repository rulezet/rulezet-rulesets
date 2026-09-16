rule Trojan_Win32_Amadey_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 ff b1 e0 00 00 00 8b 81 e4 00 00 00 03 c6 50 8b 81 dc 00 00 00 03 85 98 fe ff ff 50 ff b5 a0 fe ff ff ff 15 } 		$a_01_1 = {50 8d 85 b4 fe ff ff 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 8d 85 f8 fe ff ff 50 ff 15 } 		$a_01_2 = {41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}