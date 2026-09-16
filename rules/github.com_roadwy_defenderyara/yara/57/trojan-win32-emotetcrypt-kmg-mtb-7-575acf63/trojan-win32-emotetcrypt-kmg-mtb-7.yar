rule Trojan_Win32_EmotetCrypt_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 bf 77 02 00 00 f7 ff 8a 04 0e 0f b6 fa 8a 14 37 8d 2c 37 88 14 0e 88 45 00 8d 43 ?? 99 f7 7c 24 ?? 41 81 f9 77 02 00 00 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}