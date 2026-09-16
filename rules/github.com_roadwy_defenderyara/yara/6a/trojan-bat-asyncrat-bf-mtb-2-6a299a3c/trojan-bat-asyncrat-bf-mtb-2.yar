rule Trojan_BAT_AsyncRAT_BF_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 09 11 05 94 58 11 04 11 05 94 58 72 5f 02 00 70 28 43 00 00 0a 5d 13 06 09 11 05 94 13 0b 09 11 05 09 11 06 94 9e 09 11 06 11 0b 9e 11 05 17 58 13 05 11 05 72 5f 02 00 70 28 43 00 00 0a 32 be } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}