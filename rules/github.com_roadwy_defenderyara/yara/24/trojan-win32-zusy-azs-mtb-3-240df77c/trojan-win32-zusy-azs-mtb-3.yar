rule Trojan_Win32_Zusy_AZS_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.AZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 60 60 24 10 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d } 		$a_01_1 = {c6 85 06 ff ff ff 52 c6 85 07 ff ff ff 68 c6 85 08 ff ff ff 63 c6 85 09 ff ff ff 32 c6 85 0a ff ff ff 74 c6 85 0b ff ff ff 4f c6 85 0c ff ff ff 59 c6 85 0d ff ff ff 57 c6 85 0e ff ff ff 31 c6 85 0f ff ff ff 6c c6 85 10 ff ff ff 49 c6 85 11 ff ff ff 43 c6 85 12 ff ff ff 52 c6 85 13 ff ff ff 30 c6 85 14 ff ff ff 59 c6 85 15 ff ff ff 58 c6 85 16 ff ff ff 4e c6 85 17 ff ff ff 72 c6 85 18 ff ff ff 54 c6 85 19 ff ff ff 6d c6 85 1a ff ff ff 46 c6 85 1b ff ff ff 74 c6 85 1c ff ff ff 5a c6 85 1d ff ff ff 51 c6 85 1e ff ff ff 3d c6 85 1f ff ff ff 3d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}