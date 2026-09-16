rule Trojan_AndroidOS_Joker_K_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {1a 00 39 09 6e 20 f6 09 05 00 0c 05 21 50 12 01 35 01 32 00 46 02 05 01 6e 10 01 0a 02 00 0c 03 1a 04 bc 27 6e 20 f7 09 43 00 0a 03 38 03 21 00 1a 03 6c 09 6e 20 f6 09 32 00 0c 02 21 23 12 14 37 43 17 00 46 05 02 04 6e 10 01 0a 05 00 0c 05 1a 00 00 00 1a 01 3d 03 6e 30 f5 09 15 00 0c 05 1a 01 b5 04 6e 30 f5 09 15 00 0c 05 11 05 d8 01 01 01 28 cf 12 05 11 05 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}