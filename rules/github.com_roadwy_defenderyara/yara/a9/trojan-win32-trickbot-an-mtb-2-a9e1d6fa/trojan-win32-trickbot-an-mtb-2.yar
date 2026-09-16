rule Trojan_Win32_Trickbot_AN_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.AN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 6a 12 8b 45 04 83 c0 18 5b 8b f0 53 51 8b 0f 8b 06 33 c1 88 07 46 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}