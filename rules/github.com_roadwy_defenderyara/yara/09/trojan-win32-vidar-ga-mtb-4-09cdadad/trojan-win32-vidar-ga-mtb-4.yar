rule Trojan_Win32_Vidar_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f8 8b 4d f0 8d 14 01 8b 4d f4 31 55 fc 8b f0 d3 ee } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}