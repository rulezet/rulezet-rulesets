rule Trojan_Win32_Emotet_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 8d 2c 3b 88 1c 28 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 8a 14 02 88 55 00 3b de } 		$a_01_1 = {8b 54 24 18 0f b6 14 1a 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f6 8a 03 43 83 6c 24 14 01 8b fa 8a 14 0f 88 04 0f 88 53 ff 89 7c 24 10 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}