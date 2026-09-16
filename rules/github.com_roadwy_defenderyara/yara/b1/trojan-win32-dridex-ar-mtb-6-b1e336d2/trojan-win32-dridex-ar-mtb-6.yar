rule Trojan_Win32_Dridex_AR_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 2c 8b 7c 24 28 81 c7 bb ef 21 47 83 d1 00 89 7c 24 28 89 4c 24 2c 3c 00 89 54 24 0c 88 44 24 0b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}