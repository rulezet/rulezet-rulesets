rule Trojan_Win32_Netwire_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Netwire.AA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ca 88 55 ff 80 75 ff dc 8b da c1 e9 08 8b c2 c1 eb 10 80 f1 24 c1 e8 18 80 f3 35 34 37 80 f9 14 75 0f 80 fb 01 75 0a 84 c0 75 06 80 7d ff e9 74 03 42 eb cb } 		$a_01_1 = {8b c2 8d 8d 08 fd ff ff 83 e0 03 03 ca 83 c2 06 0f b6 44 05 f8 30 01 8d 04 0e 83 e0 03 0f b6 44 05 f8 30 41 01 8d 04 0f 83 e0 03 0f b6 44 05 f8 30 41 02 8d 04 0b 83 e0 03 0f b6 44 05 f8 30 41 03 8b 45 f4 03 c1 83 e0 03 0f b6 44 05 f8 30 41 04 8b 45 f0 03 c1 83 e0 03 0f b6 44 05 f8 30 41 05 81 fa e2 02 00 00 72 97 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}