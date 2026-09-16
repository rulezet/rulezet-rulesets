rule Trojan_Win32_EmotetCrypt_AV_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 08 2b ca 8b 55 08 89 0a 5e 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}