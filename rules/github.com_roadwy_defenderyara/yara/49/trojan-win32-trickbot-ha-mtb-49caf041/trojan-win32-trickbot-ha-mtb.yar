rule Trojan_Win32_TrickBot_HA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f3 41 8a 44 55 00 30 44 31 ff 3b cf 75 } 		$a_01_1 = {0f b6 11 c1 c8 0d 41 03 c2 80 79 ff 00 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}