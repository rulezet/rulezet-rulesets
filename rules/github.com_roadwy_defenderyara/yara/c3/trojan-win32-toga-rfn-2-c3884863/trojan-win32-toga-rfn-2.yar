rule Trojan_Win32_Toga_rfn_2{
	meta:
		description = "Trojan:Win32/Toga!rfn,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f bf d0 8b 85 b0 fe ff ff 8d 8d 54 ff ff ff 33 c2 50 51 ff 15 ?? ?? ?? ?? 8d 95 c4 fe ff ff 8d 85 54 ff ff ff 52 8d 8d 44 ff ff ff } 		$a_01_1 = {8b c8 8b c6 99 f7 f9 c7 45 c4 03 00 00 00 89 55 cc 8b 55 e0 52 ff d7 8b c8 8b c6 99 f7 f9 8d 45 c4 8d 8d 34 ff ff ff } 		$a_01_2 = {8b 55 e0 89 45 bc 52 c7 45 b4 03 00 00 00 ff d7 8b c8 8b c6 99 f7 f9 c7 45 c4 03 00 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}