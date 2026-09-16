rule Trojan_Win32_TrickBot_R_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 09 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 3b 4d 10 74 4e 8b 55 08 89 55 ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 8a 11 88 55 ?? 83 45 ?? 01 80 7d ?? 00 75 ee 8b 45 ?? 2b 45 ?? 89 45 ec 8b 45 ?? 33 d2 f7 75 ec 8b 4d 08 0f be 14 11 8b 45 0c 03 45 ?? 0f b6 08 33 ca 8b 55 0c 03 55 ?? 88 0a eb a1 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}