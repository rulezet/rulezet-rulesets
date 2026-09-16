rule Trojan_Win64_FusionBlaze_A_dha{
	meta:
		description = "Trojan:Win64/FusionBlaze.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 10 57 48 83 ec 70 bf 01 00 00 00 8b d7 44 8d 47 05 8d 4f 01 ff 15 ?? ?? ?? ?? 89 7c 24 50 33 ff } 		$a_01_1 = {48 8b d8 48 89 7c 24 40 48 89 7c 24 38 48 8d 84 24 80 00 00 00 44 8d 4f 0c 4c 8d 44 24 50 48 89 44 24 30 48 8d 44 } 		$a_01_2 = {24 60 44 89 4c 24 28 ba 04 00 00 98 48 8b cb c7 44 24 54 00 f4 01 00 48 89 44 24 20 c7 44 24 58 e8 03 00 00 89 bc } 		$a_03_3 = {24 80 00 00 00 ff 15 ?? ?? ?? ?? 83 f8 ff 48 0f 44 df 48 8b c3 48 8b 9c 24 88 00 00 00 48 83 c4 70 5f c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}