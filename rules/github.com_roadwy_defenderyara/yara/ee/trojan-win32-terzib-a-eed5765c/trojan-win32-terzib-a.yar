rule Trojan_Win32_Terzib_A{
	meta:
		description = "Trojan:Win32/Terzib.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 3b c3 7e 0e 8a 88 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? eb ed } 		$a_01_1 = {44 45 4c 20 2f 51 20 2f 53 20 22 25 73 5c 68 69 73 74 6f 72 79 } 		$a_01_2 = {43 6f 6f 6b 69 65 3a 20 2f 73 65 61 72 63 68 3f 68 6c 3d 65 6e 3d 71 3d } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}