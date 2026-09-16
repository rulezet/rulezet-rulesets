rule Trojan_Win32_Zusy_AZS_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.AZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 ca c1 ea 08 33 34 8d c0 6a 47 00 0f b6 d2 8b ce 33 48 18 8b 14 95 c0 6e 47 00 89 75 f8 89 4d f8 8b 4d e4 c1 e9 10 0f b6 c9 33 14 8d c0 72 47 00 8b 4d ec c1 e9 18 33 14 8d c0 76 47 00 0f b6 cb 33 14 8d c0 6a 47 00 } 		$a_01_1 = {8b cb 33 50 10 c1 e9 10 89 55 f0 0f b6 d1 8b 4d ec 8b 14 95 c0 72 47 00 c1 e9 08 0f b6 c9 33 14 8d c0 6e 47 00 8b 4d dc c1 e9 18 33 14 8d c0 76 47 00 89 55 fc 8b 55 e4 8b 7d fc 0f b6 ca 33 3c 8d c0 6a 47 00 8b cf 33 48 14 89 7d fc } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}