rule Trojan_Win32_ChChes_G_dha{
	meta:
		description = "Trojan:Win32/ChChes.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 db 74 19 8d 14 3e 8b 7d fc 8a 0c 11 32 0c 38 40 8b 7d 10 88 0a 8b 4d 08 3b c3 72 e7 3b 75 f8 76 0e 57 68 ?? ?? ?? ?? e8 31 00 00 00 83 c4 08 8b 45 0c 46 8b 4d 08 3b f0 72 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}