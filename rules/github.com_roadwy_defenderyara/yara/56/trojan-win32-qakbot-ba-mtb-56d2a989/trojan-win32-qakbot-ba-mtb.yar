rule Trojan_Win32_QakBot_BA_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f 88 01 41 83 ea ?? 75 f5 } 		$a_03_1 = {8b c1 83 e0 ?? 8a 44 10 ?? 30 04 31 41 3b cf 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}