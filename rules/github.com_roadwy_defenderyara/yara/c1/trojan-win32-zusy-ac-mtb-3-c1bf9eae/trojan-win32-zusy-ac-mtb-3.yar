rule Trojan_Win32_Zusy_AC_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d7 e8 8a ff ff ff 85 c0 74 30 8b 75 fc 33 c9 85 f6 74 1e 0f b7 04 4b 33 d2 c7 45 fc 34 00 00 00 f7 75 fc 66 8b 44 55 90 66 89 04 4b 41 3b ce 72 e2 33 c0 66 89 04 1f 40 eb 02 } 		$a_01_1 = {57 68 30 22 40 00 53 ff d6 e8 82 f8 ff ff 68 20 32 40 00 53 85 c0 74 76 ff d6 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}