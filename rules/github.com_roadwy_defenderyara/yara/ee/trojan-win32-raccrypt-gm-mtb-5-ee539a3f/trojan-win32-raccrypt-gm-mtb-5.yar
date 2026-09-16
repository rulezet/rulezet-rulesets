rule Trojan_Win32_Raccrypt_GM_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 3c 00 c1 ?? 04 03 [0-04] c1 [0-01] 05 03 [0-06] 33 ?? 33 } 		$a_02_1 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 3c 00 c1 ?? 05 03 [0-06] 68 b9 79 37 9e [0-06] 33 [0-06] 33 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}