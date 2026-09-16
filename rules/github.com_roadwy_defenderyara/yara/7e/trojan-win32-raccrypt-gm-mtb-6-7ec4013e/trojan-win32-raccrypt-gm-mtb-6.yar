rule Trojan_Win32_Raccrypt_GM_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 55 7b 11 c7 [0-05] 8e e6 d8 1e c7 [0-05] 7b 0c db 13 c7 [0-05] a6 c3 f8 4a c7 [0-05] 51 b7 cd 49 c7 [0-05] 29 66 56 72 c7 [0-05] ed ?? ?? 49 c7 [0-05] 18 61 f3 05 } 		$a_02_1 = {a5 28 36 47 c7 [0-05] b7 e0 73 4c c7 [0-05] 02 97 13 70 c7 [0-05] 0d d2 eb 21 c7 [0-05] 05 3d e8 27 c7 [0-05] 86 38 39 19 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}