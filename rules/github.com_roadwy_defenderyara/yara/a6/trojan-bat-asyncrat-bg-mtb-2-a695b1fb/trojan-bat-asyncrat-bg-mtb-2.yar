rule Trojan_BAT_AsyncRAT_BG_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 75 6a 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 6a 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 42 02 00 0a 26 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}