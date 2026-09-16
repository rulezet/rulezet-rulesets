rule Trojan_Win32_Zusy_KK_MTB_6{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 85 b0 fe ff ff 00 00 00 00 8d 85 f0 fe ff ff 89 44 24 0c 8d 85 b0 fe ff ff 89 44 24 08 8b 45 10 c7 85 f0 fe ff ff 00 00 00 00 89 44 24 04 8b 45 0c 89 04 24 } 		$a_01_1 = {c7 41 78 00 00 00 00 83 c1 08 c7 41 74 00 00 00 00 39 ce } 		$a_01_2 = {e8 5d 10 00 00 b9 35 00 00 00 31 d2 f7 f1 8a 44 15 b2 88 04 33 46 eb e3 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}