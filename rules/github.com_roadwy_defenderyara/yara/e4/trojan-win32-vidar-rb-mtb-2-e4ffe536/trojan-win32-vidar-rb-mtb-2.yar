rule Trojan_Win32_Vidar_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 8a 0a 0f b6 d9 8d 84 85 ?? ?? ff ff 39 18 75 08 8b 45 fc 88 0c 10 eb 0a 8a 00 32 c1 8b 4d fc 88 04 11 ff 45 f8 } 	condition:
		((#a_03_0  & 1)*6) >=6
 
}