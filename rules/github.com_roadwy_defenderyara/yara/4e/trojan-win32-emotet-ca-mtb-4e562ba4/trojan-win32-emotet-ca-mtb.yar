rule Trojan_Win32_Emotet_CA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f8 33 d2 8b c3 f7 f1 8b ce 52 e8 ?? ?? ?? ?? 8a 00 30 07 43 3b 5d 20 72 } 		$a_02_1 = {33 d2 f7 f1 52 8b 4d 1c e8 ?? ?? ?? ?? 8b 55 e8 8a 0a 32 08 8b 55 e8 88 0a eb } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}