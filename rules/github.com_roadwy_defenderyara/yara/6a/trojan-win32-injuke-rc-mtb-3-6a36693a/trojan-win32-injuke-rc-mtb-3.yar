rule Trojan_Win32_Injuke_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Injuke.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 85 50 ff ff ff 3c 00 00 00 c7 85 54 ff ff ff 00 04 00 00 b8 ?? ?? ?? ?? 89 85 60 ff ff ff 8d 85 50 ff ff ff 50 e8 99 38 f6 ff b8 c4 7e 00 00 b8 c4 7e 00 00 } 		$a_03_1 = {b8 c4 7e 00 00 ff 75 f4 ff 35 ?? ?? ?? ?? ff 75 ec 31 c9 03 4d e8 ff e1 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}