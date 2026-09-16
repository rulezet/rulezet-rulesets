rule Trojan_Win32_Almanahe_D{
	meta:
		description = "Trojan:Win32/Almanahe.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 37 33 c0 8a 90 90 ?? ?? ?? ?? 80 f2 65 88 54 05 a0 40 83 f8 ?? 7c ed } 		$a_01_1 = {41 72 70 50 6c 75 67 69 6e 2e 64 6c 6c 00 44 4c 50 49 6e 69 74 00 44 4c 50 54 65 72 6d 69 6e 61 74 65 00 44 4c 50 55 70 64 61 74 65 00 44 4c 50 56 65 72 73 69 6f 6e 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}