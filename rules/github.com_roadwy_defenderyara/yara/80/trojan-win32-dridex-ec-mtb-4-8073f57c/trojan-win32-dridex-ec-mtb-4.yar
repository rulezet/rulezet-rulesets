rule Trojan_Win32_Dridex_EC_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {b0 e5 c6 44 24 33 74 8a 4c 24 33 8a 54 24 1f 88 54 24 51 38 c8 0f 84 17 ff ff ff eb 89 31 c0 c7 44 24 2c 1e 06 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}