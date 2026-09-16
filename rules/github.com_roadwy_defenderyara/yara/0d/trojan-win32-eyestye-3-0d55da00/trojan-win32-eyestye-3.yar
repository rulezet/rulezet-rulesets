rule Trojan_Win32_EyeStye_3{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 35 30 20 4f 70 65 6e 69 6e 67 20 42 49 4e 41 52 59 20 6d 6f 64 65 20 64 61 74 61 20 63 6f 6e 6e 65 63 74 69 6f 6e } 		$a_00_1 = {66 74 70 62 63 2e 64 6c 6c } 		$a_00_2 = {2d 72 77 2d 72 2d 2d 72 2d 2d 20 31 20 30 20 30 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}