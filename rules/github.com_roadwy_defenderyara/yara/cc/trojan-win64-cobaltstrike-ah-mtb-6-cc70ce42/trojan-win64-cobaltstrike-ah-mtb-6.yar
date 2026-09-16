rule Trojan_Win64_CobaltStrike_AH_MTB_6{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 10 83 c2 01 48 83 c0 01 0f b6 d2 48 39 c8 75 ef } 		$a_01_1 = {58 51 43 40 56 45 52 6b 7a 5e 54 45 58 44 58 51 43 6b 60 5e 59 53 58 40 44 6b 74 42 45 45 52 59 43 61 52 45 44 5e 58 59 6b 65 42 59 37 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}