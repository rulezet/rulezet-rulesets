rule Trojan_Win32_Rozena_MA_MTB{
	meta:
		description = "Trojan:Win32/Rozena.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b 4d f0 8b 55 f0 88 14 08 8b 45 f0 89 45 ec ff 45 f0 eb } 		$a_03_1 = {0f be 0c 11 31 c8 90 0a 12 00 8b 45 ?? 8b 4d 0c 8b 55 [0-09] 8b 4d 10 8b 55 ?? 88 04 11 8b 45 ?? 89 45 ?? ff 45 ?? e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}