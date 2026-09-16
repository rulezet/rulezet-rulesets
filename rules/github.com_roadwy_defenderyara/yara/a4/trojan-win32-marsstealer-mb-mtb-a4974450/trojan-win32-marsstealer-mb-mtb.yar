rule Trojan_Win32_MarsStealer_MB_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 f9 02 33 c1 0f b7 15 ?? ?? ?? 00 c1 fa 03 33 c2 0f b7 0d ?? ?? ?? 00 c1 f9 05 33 c1 83 e0 01 a3 ?? ?? ?? 00 } 		$a_02_1 = {33 d2 b9 24 00 00 00 f7 f1 8b 85 e4 fe ff ff 8a 8a ?? ?? ?? 00 88 8c 05 f8 fe ff ff } 	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5) >=10
 
}