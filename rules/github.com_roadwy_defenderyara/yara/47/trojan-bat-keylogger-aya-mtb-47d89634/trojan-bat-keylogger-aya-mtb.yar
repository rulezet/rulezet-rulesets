rule Trojan_BAT_Keylogger_AYA_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 68 61 6f 73 57 6f 72 6d } 		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 } 		$a_01_2 = {49 6e 66 65 63 74 53 79 73 74 65 6d } 		$a_01_3 = {52 75 6e 50 61 79 6c 6f 61 64 } 		$a_01_4 = {53 70 72 65 61 64 56 69 61 55 53 42 } 		$a_01_5 = {49 6e 66 65 63 74 4e 65 77 45 78 65 73 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}