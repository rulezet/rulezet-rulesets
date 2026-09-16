rule Trojan_Win32_EmotetCrypt_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 da 8b 54 24 ?? 0f b6 14 13 8d 0c 2f 03 d6 03 c2 99 be 2b 03 00 00 f7 fe 0f b6 f2 8d 04 2e e8 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}