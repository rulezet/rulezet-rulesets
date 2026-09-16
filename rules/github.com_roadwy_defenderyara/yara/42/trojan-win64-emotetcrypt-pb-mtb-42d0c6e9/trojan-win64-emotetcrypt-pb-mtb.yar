rule Trojan_Win64_EmotetCrypt_PB_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 8b 44 ?? ?? 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}