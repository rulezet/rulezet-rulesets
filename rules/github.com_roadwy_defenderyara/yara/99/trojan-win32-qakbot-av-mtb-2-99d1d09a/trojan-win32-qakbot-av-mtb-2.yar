rule Trojan_Win32_Qakbot_AV_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 55 fc 5a d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 29 c9 0b 0c e4 83 c4 04 89 4d f8 83 e1 00 31 d9 83 e0 00 31 c8 8b 4d f8 aa 49 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}