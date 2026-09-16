rule Trojan_Win32_Cridex_AR_MTB_10{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 51 03 05 2c f9 04 01 03 d6 89 45 00 6b ca 52 83 c5 04 2b cf 03 f1 83 6c 24 } 		$a_01_1 = {83 44 24 10 04 81 c3 90 4b 08 01 69 c1 3e 5c 01 00 89 1e 8b f2 2b f0 2b 74 24 14 8d 4e 08 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}