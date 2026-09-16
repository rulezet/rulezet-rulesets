rule Trojan_Win32_Guloader_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {52 53 56 e8 00 00 00 00 5a 81 c2 ?? ?? 00 00 8d 9a ?? ?? 00 00 6b f6 00 69 f6 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 31 32 83 c2 04 39 da 72 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}