rule Trojan_Win32_RedLine_BS_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 d0 c1 e0 05 32 45 ef 89 c3 0f b6 4d ef 8b 55 f0 8b 45 0c 01 d0 8d 14 0b 88 10 8b 55 f0 8b 45 0c 01 d0 0f b6 10 0f b6 5d ef 8b 4d f0 8b 45 0c 01 c8 29 da 88 10 83 45 f0 01 8b 45 f0 3b 45 10 72 } 		$a_01_1 = {36 00 47 00 38 00 4c 00 32 00 70 00 6d 00 33 00 54 00 59 00 5c 00 55 00 4d 00 6b 00 45 00 68 00 59 00 71 00 33 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}