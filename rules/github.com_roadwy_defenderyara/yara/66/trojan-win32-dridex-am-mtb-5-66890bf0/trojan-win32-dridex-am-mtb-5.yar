rule Trojan_Win32_Dridex_AM_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 20 01 c1 88 cb 88 5c 24 5f 8a 5c 24 5f 8b 84 24 f0 00 00 00 8b 4d 08 88 1c 01 } 		$a_01_1 = {8b 45 10 8b 8c 24 04 01 00 00 8a 94 24 0f 01 00 00 32 94 24 0f 01 00 00 88 94 24 0f 01 00 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}