rule Trojan_Win32_Pikabot_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Pikabot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb 00 00 00 00 21 5d f0 e9 52 02 00 00 e9 e0 02 00 00 bb 03 00 00 00 83 c3 05 eb 07 8b 45 f0 33 d2 eb ef 53 5e eb 14 8b 45 e8 03 45 f0 e9 84 02 00 00 bb 0c 00 00 00 03 e3 eb c5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}