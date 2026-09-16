rule Trojan_Win32_EmotetCrypt_AV_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 01 88 02 88 19 0f b6 0a 0f b6 c3 03 c8 0f b6 c1 8a 8d ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 30 04 3e 46 81 fe } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}