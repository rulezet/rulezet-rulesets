rule Trojan_Win32_Emotet_V_MTB{
	meta:
		description = "Trojan:Win32/Emotet.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 51 01 8d 49 00 8a 01 41 84 c0 75 f9 2b ca 8b c6 33 d2 f7 f1 46 8a 82 ?? ?? ?? ?? 30 44 3e ff 3b f3 72 d7 8d 45 f8 50 6a 40 53 57 ff 15 ?? ?? ?? ?? 8b 45 b0 ff d0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}