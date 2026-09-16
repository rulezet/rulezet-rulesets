rule Trojan_Win32_BunituCrypt_RF_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 31 0c 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 8a a5 08 00 03 15 ?? ?? ?? ?? 33 c2 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}