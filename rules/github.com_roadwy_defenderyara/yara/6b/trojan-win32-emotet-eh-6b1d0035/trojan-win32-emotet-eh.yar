rule Trojan_Win32_Emotet_EH{
	meta:
		description = "Trojan:Win32/Emotet.EH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 6b 6c 65 72 2e 70 64 62 } 		$a_01_1 = {72 00 68 00 6b 00 6c 00 77 00 65 00 6a 00 68 00 6b 00 6c 00 23 00 4a 00 4b 00 48 00 4c 00 65 00 72 00 6b 00 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}