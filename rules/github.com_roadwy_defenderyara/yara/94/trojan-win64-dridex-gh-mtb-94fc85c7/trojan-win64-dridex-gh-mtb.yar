rule Trojan_Win64_Dridex_GH_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 83 ec 40 8b 44 24 3c 89 ca 09 c2 89 54 24 3c 48 c7 44 24 28 3a 51 d7 3d 4c 8b } 		$a_00_1 = {a0 37 b7 8d b9 8f } 		$a_00_2 = {9d 51 71 af a7 } 		$a_02_3 = {e5 44 15 de 71 f2 89 ?? ?? e6 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=13
 
}