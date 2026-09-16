rule Trojan_Win32_TrickBot_DSK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f3 41 8a 04 2a 30 44 31 ff 3b cf 75 } 		$a_01_1 = {32 23 4a 4e 4d 48 58 46 41 40 32 2a 45 44 43 31 56 7d 4a 5a 66 33 4f 4c 4b 58 4d 74 4a 7c 55 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}