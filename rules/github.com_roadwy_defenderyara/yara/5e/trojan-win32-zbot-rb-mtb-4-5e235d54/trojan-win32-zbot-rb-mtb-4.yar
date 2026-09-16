rule Trojan_Win32_Zbot_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Zbot.RB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 02 33 45 fc 8b 4d f8 89 01 c7 45 d0 16 00 00 00 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}