rule Trojan_Win32_Zusy_GNS_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f3 8d 41 f8 01 55 fc 33 d2 f7 f3 8b c1 03 f2 33 d2 f7 f3 8d 41 08 83 c1 20 03 fa 33 d2 f7 f3 01 55 f8 ff 4d f4 ?? ?? 8b 45 f8 8b 4d f0 03 c7 03 c6 01 45 fc 83 c1 65 89 4d f0 81 f9 10 50 06 00 } 		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 75 73 65 72 20 68 65 6c 6c 6f 31 32 33 20 68 65 6c 6c 78 78 78 5f 48 78 78 78 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}