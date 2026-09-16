rule Trojan_Win64_Trickbot_SH{
	meta:
		description = "Trojan:Win64/Trickbot.SH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 8b 5a 40 49 8b 7a 38 49 8b 5a 30 4d 8b 4a 28 4d 8b 42 20 49 8b 4a 10 49 8b 52 18 } 		$a_03_1 = {48 89 44 24 38 4c 89 5c 24 30 48 89 7c 24 28 48 89 5c 24 20 eb 56 [0-60] ff 12 } 		$a_01_2 = {48 89 86 a8 00 00 00 c7 46 58 00 00 00 00 48 8b 4e 08 ff 56 30 48 8b 0e 48 8b 56 08 41 b8 ff ff ff ff 45 33 c9 ff 56 18 } 		$a_01_3 = {48 8b 0e 48 8b 56 08 45 33 c0 45 33 c9 ff 56 18 48 8b 0e ff 56 28 48 c7 06 00 00 00 00 48 8b 4e 08 ff 56 28 48 c7 46 08 00 00 00 00 33 c9 ff 56 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}