rule Trojan_Win32_Emotet_P{
	meta:
		description = "Trojan:Win32/Emotet.P,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {7c 75 47 54 4a 76 46 7a 54 68 4d 53 55 6a 39 5a 66 2e 70 64 62 90 09 18 00 52 53 44 53 } 		$a_03_1 = {6b 6f 6c 73 64 65 33 32 2e 64 6c 6c 90 09 18 00 52 53 44 53 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}