rule Trojan_Win64_CobaltStrike_BS_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 d9 04 31 34 63 88 45 da 0f b6 45 da 04 31 34 75 88 45 db } 		$a_01_1 = {0f b6 54 05 d0 41 80 c0 31 0f b6 4c 05 d0 41 32 c8 44 0f b6 c2 88 4c 05 d0 48 ff c0 48 83 f8 11 72 de } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}