rule Trojan_Win32_Emotet_DT{
	meta:
		description = "Trojan:Win32/Emotet.DT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 49 46 64 72 47 6b 6d 42 65 50 73 73 2e 70 64 62 } 		$a_01_1 = {2f 64 51 57 50 49 43 6c 5f 48 75 64 65 31 76 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}