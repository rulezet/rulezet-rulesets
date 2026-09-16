rule Trojan_Win64_CobaltStrike_MK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 ee 48 89 74 24 48 49 89 f6 89 ee 49 8b 4d 00 46 8d 04 f5 00 00 00 00 c7 44 24 20 03 00 00 00 48 89 fa 4d 89 e1 e8 } 		$a_01_1 = {78 78 78 78 2e 64 6c 6c 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 52 75 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}