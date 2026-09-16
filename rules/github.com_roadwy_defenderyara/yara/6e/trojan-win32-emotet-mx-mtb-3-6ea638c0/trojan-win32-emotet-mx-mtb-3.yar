rule Trojan_Win32_Emotet_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 58 10 00 00 f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01 41 3b ee 89 4c 24 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}