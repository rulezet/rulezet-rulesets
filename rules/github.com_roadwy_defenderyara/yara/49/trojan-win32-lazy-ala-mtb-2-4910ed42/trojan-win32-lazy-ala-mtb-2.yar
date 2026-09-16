rule Trojan_Win32_Lazy_ALA_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 1c f7 ff ff 4c c6 85 1d f7 ff ff 6f c6 85 1e f7 ff ff 61 c6 85 1f f7 ff ff 64 c6 85 20 f7 ff ff 4c c6 85 21 f7 ff ff 69 c6 85 22 f7 ff ff 62 c6 85 23 f7 ff ff 72 c6 85 24 f7 ff ff 61 c6 85 25 f7 ff ff 72 c6 85 26 f7 ff ff 79 c6 85 27 f7 ff ff 57 } 		$a_01_1 = {b9 6b 00 00 00 66 89 8d 6c e8 ff ff ba 65 00 00 00 66 89 95 6e e8 ff ff b8 72 00 00 00 66 89 85 70 e8 ff ff b9 6e 00 00 00 66 89 8d 72 e8 ff ff ba 65 00 00 00 66 89 95 74 e8 ff ff b8 6c 00 00 00 66 89 85 76 e8 ff ff b9 33 00 00 00 66 89 8d 78 e8 ff ff ba 32 00 00 00 66 89 95 7a e8 ff ff b8 2e 00 00 00 66 89 85 7c e8 ff ff b9 64 00 00 00 66 89 8d 7e e8 ff ff ba 6c 00 00 00 66 89 95 80 e8 ff ff b8 6c 00 00 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}