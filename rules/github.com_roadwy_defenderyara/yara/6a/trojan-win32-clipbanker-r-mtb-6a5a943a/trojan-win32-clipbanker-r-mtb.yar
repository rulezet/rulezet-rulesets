rule Trojan_Win32_ClipBanker_R_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 69 6c 65 6e 74 20 4d 69 6e 65 72 2e 70 64 62 } 		$a_01_1 = {c7 45 d4 2b 73 73 7e 0f 28 05 00 c7 40 00 0f 11 45 c4 c7 45 d8 72 70 60 28 c7 45 dc 6f 74 70 00 8a 45 b4 30 44 0d b5 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}