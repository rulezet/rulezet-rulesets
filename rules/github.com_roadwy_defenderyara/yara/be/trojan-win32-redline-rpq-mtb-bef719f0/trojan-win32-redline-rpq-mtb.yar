rule Trojan_Win32_RedLine_RPQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 75 cc 3b f7 0f 83 81 00 00 00 8a 14 30 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d d0 88 04 31 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}