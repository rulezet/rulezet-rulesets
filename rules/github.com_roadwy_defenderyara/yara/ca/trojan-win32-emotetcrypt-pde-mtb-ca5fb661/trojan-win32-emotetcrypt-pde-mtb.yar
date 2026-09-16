rule Trojan_Win32_EmotetCrypt_PDE_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 0c 3a 33 d2 0f b6 c1 8b ce 0f b6 0c 39 03 c1 f7 35 ?? ?? ?? ?? 8b f2 ff 15 ?? ?? ?? ?? 8b 4d 18 8a 04 0b 32 04 3e 88 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}