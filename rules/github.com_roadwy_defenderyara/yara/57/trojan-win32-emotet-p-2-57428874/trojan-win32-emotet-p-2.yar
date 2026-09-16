rule Trojan_Win32_Emotet_P__2{
	meta:
		description = "Trojan:Win32/Emotet.P!!Emotet.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,28 00 28 00 01 00 00 "
		
	strings :
		$a_03_0 = {54 89 e0 83 e8 10 31 c9 89 1d ?? ?? ?? ?? 01 d8 83 c8 01 83 c1 04 83 f8 00 74 24 8f 05 ?? ?? ?? ?? 01 0d ?? ?? ?? ?? 8f 05 ?? ?? ?? ?? 83 f9 00 0f 85 ?? ?? ?? ?? 85 c0 74 05 b8 ff 00 00 00 } 	condition:
		((#a_03_0  & 1)*40) >=40
 
}