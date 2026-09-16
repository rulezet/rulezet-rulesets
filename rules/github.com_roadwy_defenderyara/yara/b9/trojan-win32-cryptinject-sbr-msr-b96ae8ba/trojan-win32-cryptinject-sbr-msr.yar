rule Trojan_Win32_CryptInject_SBR_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 78 62 6f 6d 62 } 		$a_01_1 = {4e 65 64 72 69 76 65 6e } 		$a_01_2 = {4f 76 65 72 73 6b 72 69 76 66 75 6e 6b 74 69 6f 6e } 		$a_01_3 = {73 00 74 00 72 00 69 00 6e 00 67 00 20 00 73 00 70 00 61 00 } 		$a_01_4 = {53 61 6c 69 65 6e 63 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}