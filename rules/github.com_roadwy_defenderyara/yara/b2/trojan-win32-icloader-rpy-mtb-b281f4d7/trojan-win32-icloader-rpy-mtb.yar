rule Trojan_Win32_ICLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 96 84 00 85 f5 80 00 00 da 0a 00 73 5b 0d ca 36 b8 80 00 00 d4 00 00 f8 3c 15 20 } 		$a_01_1 = {58 00 52 00 45 00 43 00 4f 00 44 00 45 00 20 00 33 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}