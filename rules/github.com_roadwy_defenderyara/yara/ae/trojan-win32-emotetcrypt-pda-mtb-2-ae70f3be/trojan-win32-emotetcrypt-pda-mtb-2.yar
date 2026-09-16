rule Trojan_Win32_EmotetCrypt_PDA_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 32 8b 44 24 ?? 02 4c 24 ?? 8b 54 24 ?? 32 0c 02 83 c0 01 83 6c 24 ?? 01 88 48 ff 89 44 24 ?? 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}