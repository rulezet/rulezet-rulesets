rule Trojan_Win32_Emotetcrypt_RWA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c1 c1 e9 08 0f b6 c0 33 8c 84 ?? ?? ?? ?? 83 ee 01 75 ?? 8b 5c 24 ?? f6 d1 8b 44 24 ?? 88 0c 03 43 89 5c 24 ?? 81 fb ce 40 00 00 73 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}