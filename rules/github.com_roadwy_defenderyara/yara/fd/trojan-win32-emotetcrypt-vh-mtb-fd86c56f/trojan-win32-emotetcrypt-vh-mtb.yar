rule Trojan_Win32_Emotetcrypt_VH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 01 30 07 8b 45 ?? 3b 75 ?? 0f 8c 90 0a 19 00 0f b6 cb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}