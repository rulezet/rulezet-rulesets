rule Trojan_Win64_CobaltStrike_BQ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 10 33 48 8d 55 b0 48 8b cb e8 [0-04] b9 10 00 00 00 0f 1f 40 00 0f 1f 84 00 00 00 00 00 0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 } 		$a_03_1 = {b9 0f 27 00 00 ff 15 [0-04] 4c 89 74 24 20 41 b9 f4 01 00 00 4c 8d 85 60 02 00 00 48 8b 54 24 60 48 8b cf } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}