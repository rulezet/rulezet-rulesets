rule Trojan_Win32_Emotet_EH_2{
	meta:
		description = "Trojan:Win32/Emotet.EH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 77 6b 6c 68 6f 6a 77 6b 6c 5c 5c 65 68 77 5c 5c 77 65 72 65 6a 57 52 4b 40 6a 6b 65 74 6a 77 72 67 2e 70 64 62 } 		$a_01_1 = {57 45 48 4b 4c 4a 57 4b 4c 23 40 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}