rule Trojan_Win32_Emotet_SK_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 76 64 66 66 78 63 64 66 73 64 78 78 7a 53 61 77 } 		$a_01_1 = {53 65 74 46 69 6c 65 53 65 63 75 72 69 74 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}