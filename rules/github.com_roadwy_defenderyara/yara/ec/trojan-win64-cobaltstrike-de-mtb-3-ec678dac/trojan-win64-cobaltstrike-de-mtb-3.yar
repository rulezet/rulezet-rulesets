rule Trojan_Win64_CobaltStrike_DE_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a } 		$a_01_1 = {89 ca 83 e2 03 41 0f b6 14 17 32 14 0f 88 14 0b 8d 51 01 83 e2 03 41 0f b6 14 17 32 54 0f 01 88 54 0b 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}