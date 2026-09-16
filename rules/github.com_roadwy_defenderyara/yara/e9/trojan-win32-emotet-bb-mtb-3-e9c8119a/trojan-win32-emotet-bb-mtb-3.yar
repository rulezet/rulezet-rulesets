rule Trojan_Win32_Emotet_BB_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.BB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 84 85 f0 f9 ff ff 8b 8d ec f9 ff ff 03 84 8d f0 f9 ff ff 99 b9 81 01 00 00 f7 f9 8b 45 08 03 45 f8 0f b6 08 33 8c 95 f0 f9 ff ff 8b 55 08 03 55 f8 88 0a e9 } 		$a_01_1 = {8a 44 8c 10 8b da 8b 54 9c 10 89 54 8c 10 0f b6 d0 89 54 9c 10 8b 44 8c 10 03 c2 99 f7 ff 0f b6 44 94 10 30 44 2e ff 3b b4 24 9c 08 00 00 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}