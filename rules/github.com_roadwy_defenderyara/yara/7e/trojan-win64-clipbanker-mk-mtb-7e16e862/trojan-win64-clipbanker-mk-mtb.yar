rule Trojan_Win64_ClipBanker_MK_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 7d 1f 0f 48 8d 55 07 48 8d 4d e7 48 0f 47 55 07 48 83 fe 0f 48 0f 47 cb 4c 3b 45 17 } 		$a_01_1 = {48 8b d7 4c 8d 05 73 ac 02 00 83 e2 3f 48 8b cf 48 c1 f9 06 48 8d 14 d2 49 8b 0c c8 c6 44 d1 38 00 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}