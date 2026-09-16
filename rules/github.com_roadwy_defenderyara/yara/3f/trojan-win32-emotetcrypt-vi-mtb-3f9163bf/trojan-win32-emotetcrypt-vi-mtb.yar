rule Trojan_Win32_Emotetcrypt_VI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 01 8b 4d ?? 30 04 ?? 47 8b 4d ?? 5e 3b 7d ?? 0f 8c 90 0a 1e 00 0f b6 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}