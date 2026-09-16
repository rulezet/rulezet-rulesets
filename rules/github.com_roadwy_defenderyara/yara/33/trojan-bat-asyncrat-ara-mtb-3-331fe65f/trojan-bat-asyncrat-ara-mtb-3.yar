rule Trojan_BAT_AsyncRAT_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 1d 1a 5d 16 2d 02 1e 5a 1f 1f 5f 1c 2c fa 63 16 2d ed 61 1a 2c 01 } 		$a_80_1 = {53 65 6c 65 6e 61 47 6f 6d 65 7a 2e 50 72 6f 67 72 61 6d } 	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}