rule Trojan_Win32_EyeStye{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {ff 00 8d 85 90 09 46 00 ff 63 c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 6e c6 85 ?? ?? ?? ff 66 c6 85 ?? ?? ?? ff 69 c6 85 ?? ?? ?? ff 67 c6 85 ?? ?? ?? ff 2e c6 85 ?? ?? ?? ff 62 c6 85 ?? ?? ?? ff 69 c6 85 ?? ?? ?? ff 6e c6 85 } 		$a_00_1 = {55 8b ec 51 51 8b 45 08 66 81 38 4d 5a 74 04 33 c0 c9 c3 56 8b 70 3c 03 f0 81 3e 50 45 00 00 } 		$a_00_2 = {5f 5f 43 4c 45 41 4e 53 57 45 45 50 5f 5f } 		$a_00_3 = {63 6c 65 61 6e 73 77 65 65 70 2e 65 78 65 } 	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=5
 
}