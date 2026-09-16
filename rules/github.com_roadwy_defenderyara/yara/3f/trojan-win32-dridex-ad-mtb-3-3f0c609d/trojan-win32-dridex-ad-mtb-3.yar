rule Trojan_Win32_Dridex_AD_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 3a 66 03 c9 66 03 ce b8 80 09 00 00 66 03 cf 8d 77 fe 66 2b c8 83 ea 08 0f b7 c1 03 f0 } 		$a_01_1 = {66 83 c1 27 0f b7 d3 66 03 c2 66 03 c6 66 03 c1 8d 4b ff 0f b7 c0 03 c8 8a 44 24 10 04 27 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}