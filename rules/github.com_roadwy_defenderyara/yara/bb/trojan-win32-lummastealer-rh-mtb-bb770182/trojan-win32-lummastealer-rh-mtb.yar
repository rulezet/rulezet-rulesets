rule Trojan_Win32_LummaStealer_RH_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 42 2e 69 6d 70 6f 72 74 73 00 10 00 00 00 10 06 00 00 10 00 00 00 10 06 00 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 60 } 		$a_01_1 = {50 45 00 00 4c 01 05 00 fe 3b 2b 68 00 00 00 00 00 00 00 00 e0 00 03 01 0b 01 0e 00 00 de 04 00 00 92 00 00 00 00 00 00 40 77 02 00 00 10 } 		$a_03_2 = {55 89 e5 53 57 56 81 ec 24 08 00 00 8b 4d 08 8d 05 44 23 ?? ?? 89 85 d4 fa ff ff 0f b7 01 89 85 08 fe ff ff 8a 8d b8 fe ff ff 88 8d b4 fe ff ff c6 45 c4 8d c6 45 c5 9b c6 45 c6 42 c6 45 c7 43 31 c9 83 f9 04 73 4c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*5) >=8
 
}