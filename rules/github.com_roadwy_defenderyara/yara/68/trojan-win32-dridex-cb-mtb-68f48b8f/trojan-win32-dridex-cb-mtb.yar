rule Trojan_Win32_Dridex_CB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 37 88 0e 0f b6 1d ?? ?? ?? ?? 83 e8 01 8a ca 2a c8 80 c1 2d 0f b6 c9 83 c6 01 3b 1d ?? ?? ?? ?? 8d 4c 11 } 		$a_01_1 = {6f 77 6e 5c 53 74 6f 72 65 5c 4f 6e 63 65 5c 42 6f 61 74 5c 61 67 72 65 65 5c 4d 65 6e 5c 4d 69 6c 65 5c 57 69 6c 6c 6d 61 67 6e 65 74 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}