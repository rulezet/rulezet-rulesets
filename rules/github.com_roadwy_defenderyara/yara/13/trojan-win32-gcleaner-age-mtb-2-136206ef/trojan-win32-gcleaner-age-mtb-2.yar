rule Trojan_Win32_GCleaner_AGE_MTB_2{
	meta:
		description = "Trojan:Win32/GCleaner.AGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7d c4 10 8d 45 b0 6a 01 0f 43 45 b0 6a 00 6a 03 ff 73 40 ff 73 3c 6a 50 50 57 ff 15 } 		$a_03_1 = {50 8b 03 03 47 28 68 e8 03 00 00 50 ff b5 c4 fe ff ff ff 15 ?? ?? ?? ?? 8b 95 e0 fe ff ff 01 13 89 85 b4 fe ff ff 8b 06 8b c8 2b 0b 81 f9 e8 } 		$a_01_2 = {31 38 35 2e 31 35 36 2e 37 33 2e 37 33 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5) >=8
 
}