rule Trojan_Win32_EmotetCrypt_KMG_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 8b 44 24 ?? 30 54 28 ?? 3b 6c 24 ?? 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}