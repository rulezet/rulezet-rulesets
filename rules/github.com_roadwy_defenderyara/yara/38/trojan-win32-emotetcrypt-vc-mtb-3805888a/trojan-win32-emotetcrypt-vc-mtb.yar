rule Trojan_Win32_Emotetcrypt_VC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8a 04 38 30 ?? 8b 45 ?? 8b 5d ?? 3b 75 ?? 7c 90 0a 23 00 03 ?? ?? ?? ?? ?? ?? 99 f7 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}