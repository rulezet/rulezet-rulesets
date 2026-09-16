rule Trojan_Win32_Raccrypt_GO_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {9f 99 a2 25 c7 85 ?? ?? ?? ?? e9 a9 1a 16 c7 85 ?? ?? ?? ?? eb 24 54 26 c7 85 ?? ?? ?? ?? 15 4f 12 30 c7 85 ?? ?? ?? ?? 35 2a da 14 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}