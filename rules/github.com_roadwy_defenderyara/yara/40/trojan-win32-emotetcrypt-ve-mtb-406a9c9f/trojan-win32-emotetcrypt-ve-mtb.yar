rule Trojan_Win32_Emotetcrypt_VE_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 11 8b c7 2b 05 ?? ?? ?? ?? 03 45 ?? 30 ?? 47 89 7d ?? 3b 7d ?? 0f 8c 90 0a 32 00 0f b6 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}