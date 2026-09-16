rule Trojan_Win32_Lokibot_AV_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8a 14 16 30 14 01 83 fe 14 75 04 33 f6 eb 01 46 30 1c 01 41 3b cf 72 e5 } 		$a_01_1 = {8a 54 35 e4 30 14 08 83 fe 14 75 04 33 f6 eb 01 46 40 3b c7 72 ea } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}