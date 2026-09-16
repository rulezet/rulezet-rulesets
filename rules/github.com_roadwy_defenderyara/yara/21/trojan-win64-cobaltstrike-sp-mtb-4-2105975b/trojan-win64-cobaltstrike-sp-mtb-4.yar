rule Trojan_Win64_CobaltStrike_SP_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 46 88 44 0c 40 41 8b c0 4d 8d 49 01 f7 f7 41 ff c0 0f b6 44 14 30 42 88 84 0c 3f 01 00 00 41 81 f8 00 01 00 00 7c d7 } 		$a_01_1 = {0f b6 84 14 40 01 00 00 44 0f b6 44 14 40 03 d8 41 03 d8 81 e3 ff 00 00 80 7d 0a ff cb 81 cb 00 ff ff ff ff c3 48 63 c3 48 8d 4c 24 40 48 03 c8 0f b6 01 88 44 14 40 48 ff c2 44 88 01 49 83 e9 01 75 bd } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}