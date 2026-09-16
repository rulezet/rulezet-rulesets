rule Trojan_Win32_QakBot_RPR_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 4d 0c 6b 11 03 52 6a 00 ff 15 } 		$a_01_1 = {8b 55 dc 83 c2 01 89 55 dc 8b 45 f0 83 e8 01 39 45 dc 7d 1a 8b 4d c4 03 4d d4 8b 55 dc 8a 44 15 d8 88 01 8b 4d d4 83 c1 01 89 4d d4 eb d2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}