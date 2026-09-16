rule Trojan_Win32_Lokibot_AZ_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AZ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ce c1 e1 05 8b fe c1 ef 02 03 cf 0f be 3a 03 cf 33 f1 42 48 e9 38 26 00 00 } 		$a_01_1 = {56 8b f1 85 f6 0f 84 1e 00 00 00 33 c9 41 2b c8 57 8b 7c 24 0c 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 4e 0f 85 e9 ff ff ff 5f 5e c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}