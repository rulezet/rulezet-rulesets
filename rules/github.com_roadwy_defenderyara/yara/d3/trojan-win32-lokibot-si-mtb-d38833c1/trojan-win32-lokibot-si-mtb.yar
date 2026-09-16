rule Trojan_Win32_lokibot_SI_MTB{
	meta:
		description = "Trojan:Win32/lokibot.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 e8 ?? ?? ?? ?? 90 05 10 01 90 43 4e 75 90 0a 80 00 8b ?? fc 03 ?? f8 90 05 10 01 90 8a ?? 90 05 10 01 90 90 05 10 02 34 80 [0-02] 90 05 10 01 90 88 ?? 90 05 10 01 90 8d 45 f8 e8 } 		$a_03_1 = {8b c2 03 c3 90 05 10 01 90 c6 00 ?? 90 05 10 01 90 43 81 fb ?? ?? ?? ?? 75 ?? 90 05 10 01 90 8b } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}