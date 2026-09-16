rule Trojan_Win64_CobaltStrike_HR_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b c1 c7 44 24 40 80 df b2 69 83 e0 0f c7 44 24 44 b4 83 06 ad c7 44 24 48 28 67 9a 31 c7 44 24 4c dc 8b 6e f5 0f 28 44 24 40 66 0f 7f 44 24 60 0f b6 44 04 60 32 84 11 88 7a 01 00 88 44 0c 50 48 ff c1 48 83 f9 0c 72 b6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}