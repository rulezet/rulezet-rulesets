rule Trojan_Win32_Emotet_DC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 e0 2b f2 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 45 e4 03 45 0c 8b 4d e8 88 0c 30 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}