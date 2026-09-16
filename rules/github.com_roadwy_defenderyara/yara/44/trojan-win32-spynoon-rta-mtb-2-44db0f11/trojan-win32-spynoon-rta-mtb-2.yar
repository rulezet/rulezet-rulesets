rule Trojan_Win32_Spynoon_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Spynoon.RTA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 ee d4 00 00 ba 86 21 01 00 4b 2d e9 5b 00 00 f7 d2 81 c1 9d 35 00 00 } 		$a_01_1 = {81 eb a8 07 00 00 b8 5b 71 00 00 f7 d3 81 fb d2 47 01 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}