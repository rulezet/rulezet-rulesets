rule Trojan_Win32_Trickbot_VIS_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.VIS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b 4d f8 8a 14 33 03 c1 83 c4 0c 30 10 41 3b 4d 10 89 4d f8 72 9f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}