rule Trojan_Win32_Zbot_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 89 c1 89 f8 83 ca 01 89 55 e8 99 f7 7d e8 01 c1 8b 45 cc 03 4d 08 09 f8 03 45 08 ff 4d e4 8a 10 88 55 e8 8a 11 88 10 8a 45 e8 88 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}