rule Trojan_Win32_Zbot_RPQ_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 ff 8b ce 23 4d e8 8a 55 fe 81 e1 ?? ?? 00 00 83 e9 10 d2 e0 8a 4d 0c 80 e9 14 d2 ea 8b 4d 08 81 e1 ?? ?? 00 00 0a c2 8b 55 f0 81 f1 ?? ?? 00 00 88 84 11 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}