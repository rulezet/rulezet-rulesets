rule Trojan_Win64_CobaltStrike_BK_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 c9 08 e8 [0-04] 41 0f b6 0c 3c 31 c1 41 33 0e 49 ff c5 41 89 4e 20 49 83 fd 08 75 06 48 ff c7 45 31 ed 49 83 c6 04 4c 39 f5 75 } 		$a_01_1 = {63 6d 64 20 2f 63 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}