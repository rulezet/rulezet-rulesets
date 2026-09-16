rule Trojan_Win32_Small{
	meta:
		description = "Trojan:Win32/Small,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc a3 68 aa 40 00 c7 45 ?? 10 00 00 00 8d 45 ?? 50 8d 85 ?? f9 ff ff 50 e8 ?? dd ff ff 8d 85 ?? f9 ff ff e8 } 		$a_02_1 = {55 8b ec 81 c4 ?? f8 ff ff 53 56 57 [0-01] 31 c0 50 b9 61 72 79 41 64 03 40 30 51 68 4c 69 62 72 78 0f 8b 40 0c 31 d2 8b 40 1c 8b 00 8b 40 08 eb 0d 8b 40 34 31 d2 8d 40 7c 31 d2 8b 40 3c b9 cf 6e 61 64 83 c1 7d 51 54 50 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}