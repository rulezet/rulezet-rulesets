rule Trojan_Win32_Zbot_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 00 c2 00 00 b0 7d b4 c5 30 06 46 28 26 46 fe c0 fe c4 83 e9 02 75 f1 c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}