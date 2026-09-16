rule Trojan_Win32_ShipUp_GZY_MTB_2{
	meta:
		description = "Trojan:Win32/ShipUp.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 c4 89 55 cc 8b 45 dc 89 45 fc 8b 4d c8 89 4d ec 8b 55 c4 89 55 f4 8b 45 c4 89 45 d8 8b 4d ec 89 4d e0 8b 55 d8 89 55 f8 8b 45 f8 8b 08 33 4d e0 8b 55 f8 89 0a c7 45 c0 41 3c 00 00 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}