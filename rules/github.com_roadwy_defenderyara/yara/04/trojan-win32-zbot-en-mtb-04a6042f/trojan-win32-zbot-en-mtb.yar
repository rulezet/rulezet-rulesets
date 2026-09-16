rule Trojan_Win32_Zbot_EN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 0c 02 8b 55 f4 89 d0 c1 e0 02 01 d0 c1 e0 03 01 c8 05 f8 00 00 00 89 45 e0 8b 45 e0 8b 50 10 8b 45 08 8b 00 89 c1 8b 45 e0 8b 40 14 01 c8 89 c3 8b 45 e4 8b 48 34 8b 45 e0 8b 40 0c 01 c8 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}