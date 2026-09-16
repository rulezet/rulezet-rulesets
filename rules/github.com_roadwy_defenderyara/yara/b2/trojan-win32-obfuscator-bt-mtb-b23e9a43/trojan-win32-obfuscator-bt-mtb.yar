rule Trojan_Win32_Obfuscator_BT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 8d 84 02 ?? ?? ?? ?? 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 ?? ?? ?? ?? 8b 55 08 89 0a 8b e5 5d c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}