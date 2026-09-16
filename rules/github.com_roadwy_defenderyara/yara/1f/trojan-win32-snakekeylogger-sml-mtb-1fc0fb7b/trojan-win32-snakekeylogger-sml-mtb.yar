rule Trojan_Win32_SnakeKeylogger_SML_MTB{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {61 6f 72 74 6f 67 72 61 70 68 69 63 } 		$a_81_1 = {66 6c 6f 72 69 6b 65 6e } 		$a_81_2 = {62 69 6c 69 6f 75 73 6e 65 73 73 65 73 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}