rule Trojan_Win32_EmotetCrypt_KM_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 0f b6 4d ?? 8a 0c 11 30 08 ff 45 ?? 8b 45 ?? 3b 45 ?? 0f 8c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}