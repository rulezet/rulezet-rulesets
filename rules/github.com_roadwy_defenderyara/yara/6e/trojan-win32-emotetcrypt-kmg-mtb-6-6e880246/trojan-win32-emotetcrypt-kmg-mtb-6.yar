rule Trojan_Win32_EmotetCrypt_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 bf 9d 02 00 00 f7 ff 0f b6 c2 8a 0c 08 8b 45 ?? 30 08 ff 45 ?? 8b 45 ?? 3b 45 ?? 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}