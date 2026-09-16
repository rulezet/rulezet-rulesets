rule Trojan_Win32_Marijku_A_2{
	meta:
		description = "Trojan:Win32/Marijku.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 64 26 08 00 8b 4d f0 51 ff 15 ?? ?? ?? 10 89 45 a8 8b 55 f0 52 ff 15 ?? ?? ?? 10 8b 4d f4 64 89 0d 00 00 00 00 } 		$a_00_1 = {2f 70 61 72 61 2e 68 74 6d 3f 72 6e 64 3d 25 64 } 		$a_01_2 = {61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 } 	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}