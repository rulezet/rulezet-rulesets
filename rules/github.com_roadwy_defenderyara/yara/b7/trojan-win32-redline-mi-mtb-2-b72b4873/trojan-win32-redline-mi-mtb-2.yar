rule Trojan_Win32_Redline_MI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e7 89 c8 29 d0 d1 e8 01 c2 89 c8 c1 ea 06 6b d2 5b 29 d0 89 c2 89 f0 c1 ea 02 f6 a2 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 c1 01 81 f9 7e 07 00 00 75 } 		$a_01_1 = {61 6b 71 68 66 72 77 79 69 75 65 78 72 73 66 67 65 70 6d 6a } 		$a_01_2 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}