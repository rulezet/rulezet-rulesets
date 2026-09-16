rule Trojan_Win32_Dridex_DF_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DF!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 03 00 00 00 0f c2 c8 02 83 c2 04 83 c2 04 } 		$a_01_1 = {29 d7 19 c6 89 74 24 14 89 7c 24 10 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}