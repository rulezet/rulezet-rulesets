rule Trojan_BAT_AsyncRAT_ARA_MTB_7{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 11 05 91 13 06 03 11 05 07 5d 91 13 07 11 07 08 20 00 01 00 00 5d 58 11 05 58 20 00 01 00 00 5d 13 08 11 06 11 08 19 5a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 09 06 11 05 11 09 9c 00 11 05 17 58 13 05 11 05 02 8e 69 fe 04 13 0a 11 0a 2d ac } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}