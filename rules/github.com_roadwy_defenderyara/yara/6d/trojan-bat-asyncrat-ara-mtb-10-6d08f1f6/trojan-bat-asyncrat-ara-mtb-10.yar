rule Trojan_BAT_AsyncRAT_ARA_MTB_10{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 8e 69 5d 1f 17 59 1f 17 58 02 08 02 8e 69 5d 1f 16 58 1f 16 59 91 07 08 07 8e 69 5d 1b 58 1a 58 1f 0b 58 1f 14 59 18 58 18 59 91 61 02 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 02 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3c 26 08 19 2c f8 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 3e } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}