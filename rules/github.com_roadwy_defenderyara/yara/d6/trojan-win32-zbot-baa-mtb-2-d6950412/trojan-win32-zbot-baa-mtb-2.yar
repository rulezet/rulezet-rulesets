rule Trojan_Win32_Zbot_BAA_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 33 f8 83 d3 ?? f7 d6 83 c6 ?? 01 d6 83 ee ?? 29 d2 31 f2 89 31 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}