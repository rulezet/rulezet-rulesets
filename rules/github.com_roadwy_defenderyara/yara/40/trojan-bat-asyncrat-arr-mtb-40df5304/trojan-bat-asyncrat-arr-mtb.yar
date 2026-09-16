rule Trojan_BAT_AsyncRAT_ARR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 0d 0a 09 05 08 12 1d 0a 1e 01 02 0c 0d 0b 0f 07 05 1e 00 14 1e 00 01 00 00 1e 01 1e 01 09 06 } 		$a_01_1 = {09 04 0a 02 05 08 13 07 05 14 1e 00 01 00 00 14 1e 00 01 00 00 1e 01 1e 00 09 0d 07 04 14 1e 00 } 	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}