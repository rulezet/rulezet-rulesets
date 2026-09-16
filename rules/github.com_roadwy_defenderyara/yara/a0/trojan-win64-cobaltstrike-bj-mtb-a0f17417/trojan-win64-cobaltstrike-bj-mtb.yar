rule Trojan_Win64_CobaltStrike_BJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 4d 8d 40 01 49 83 f9 64 49 0f 45 c9 0f b6 44 0c 30 41 30 40 ff 33 c0 49 83 f9 64 4c 8d 49 01 0f 45 c2 41 ff c2 8d 50 01 41 81 fa [0-04] 72 } 		$a_01_1 = {4d 63 56 73 6f 43 66 67 47 65 74 4f 62 6a 65 63 74 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}