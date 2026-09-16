rule Trojan_Win32_CryptInject_2{
	meta:
		description = "Trojan:Win32/CryptInject,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 f6 2b 37 f7 de 83 c7 05 4f f7 d6 83 ee d7 01 de 83 ee 00 4e 8d 1e 56 8f 41 00 8d 49 04 83 ea 03 4a 85 d2 75 da 83 c4 04 8b 4c 24 fc 8d 15 ?? ?? ?? ?? ff 32 ff d1 } 		$a_01_1 = {c6 00 6b c6 40 01 65 c6 40 02 72 c6 40 03 6e c6 40 04 65 c6 40 05 6c c6 40 06 33 50 8d 05 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}