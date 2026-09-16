rule Trojan_Win32_CryptInject_BH_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 85 d0 f7 ff ff 03 85 ?? ?? ?? ?? 89 85 d0 f7 ff ff 8b ?? d4 f7 ff ff 33 ?? b8 f7 ff ff 89 ?? d4 f7 ff ff 8b ?? d4 f7 ff ff 33 ?? d0 f7 ff ff 89 ?? d0 f7 ff ff 8b ?? cc f7 ff ff 2b ?? d0 f7 ff ff 89 85 cc f7 ff ff 8b ?? cc f7 ff ff c1 ?? 04 89 ?? d4 f7 ff ff 81 3d ?? ?? ?? ?? 93 04 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}