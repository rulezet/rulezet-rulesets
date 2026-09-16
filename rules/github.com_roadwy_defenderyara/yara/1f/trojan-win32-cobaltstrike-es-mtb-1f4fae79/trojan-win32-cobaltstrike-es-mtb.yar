rule Trojan_Win32_CobaltStrike_ES_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 52 70 37 30 } 		$a_01_1 = {7a 6b 50 78 33 30 30 39 } 		$a_01_2 = {6d 67 75 72 37 33 30 79 77 31 2e 64 6c 6c } 		$a_01_3 = {64 72 69 76 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}