rule Trojan_Win32_Glupteba_G_MSR{
	meta:
		description = "Trojan:Win32/Glupteba.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c2 89 44 24 28 89 2d c0 a4 7e 00 8b 44 24 28 29 44 24 14 81 3d e4 14 14 05 d5 01 00 00 75 27 } 		$a_01_1 = {c1 ea 05 89 54 24 18 c7 05 88 33 0d 05 2e ce 50 91 8b 44 24 3c 01 44 24 18 81 3d e4 14 14 05 12 09 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}