rule Trojan_Win32_Zbot_BAB_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 30 5f d3 cf 68 7d 26 80 60 5a 03 54 24 0c 31 d7 89 3e 81 e1 00 00 00 00 f7 df 29 f9 f7 df c1 e9 03 85 ed 0f } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}