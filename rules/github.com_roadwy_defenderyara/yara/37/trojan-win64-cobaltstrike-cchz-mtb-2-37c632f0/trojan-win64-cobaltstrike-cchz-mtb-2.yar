rule Trojan_Win64_CobaltStrike_CCHZ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 45 4f 8b 55 50 89 55 48 88 45 47 0f be 45 47 33 45 48 69 c0 ?? ?? ?? ?? 89 45 50 eb } 		$a_01_1 = {48 8b 45 58 48 8d 50 01 48 89 55 58 0f b6 00 88 45 4f 80 7d 4f 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}