rule Trojan_Win32_Emotet_DJ_2{
	meta:
		description = "Trojan:Win32/Emotet.DJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 74 6a 68 65 57 52 4a 4b 65 79 57 59 40 23 79 68 4a 74 72 6a 45 52 2e 70 64 62 } 		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 50 00 72 00 69 00 6e 00 74 00 49 00 73 00 6f 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 48 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}