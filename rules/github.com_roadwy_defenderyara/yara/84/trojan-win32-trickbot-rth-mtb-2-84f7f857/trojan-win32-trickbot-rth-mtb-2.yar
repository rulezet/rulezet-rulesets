rule Trojan_Win32_Trickbot_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 d1 03 f1 89 54 24 ?? 8a 00 89 74 24 ?? 88 44 24 ?? 8b 44 24 ?? 33 ff 33 ed 66 8b 3e 8b 74 24 ?? 8d 3c be 8b 32 8a 54 24 ?? 03 f9 03 f1 84 d2 74 ?? 8b 54 24 ?? 8b de 2b da 8a 14 03 84 d2 74 } 		$a_01_1 = {38 45 31 35 41 73 74 32 52 29 74 31 5a 42 4d } 	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}