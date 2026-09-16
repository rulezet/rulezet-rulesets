rule Trojan_Win32_Dridex_AA_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 8a f2 66 3b c6 74 24 0f b7 01 0f af d8 8a d3 2a 54 24 10 80 ea 35 0f b6 c2 8a f2 66 3b c7 74 0b } 		$a_01_1 = {0f b6 c1 66 3b c7 74 26 0f b7 02 0f af d8 8a cb 2a 4c 24 10 80 e9 35 0f b6 c1 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}