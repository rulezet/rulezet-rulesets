rule Trojan_BAT_Injector_AH_MTB{
	meta:
		description = "Trojan:BAT/Injector.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_81_0 = {43 61 6e 74 20 43 72 65 61 74 65 20 50 72 6f 63 65 73 73 2e 2e 21 } 		$a_01_1 = {24 66 33 38 32 38 30 63 62 2d 30 35 31 39 2d 34 32 63 32 2d 61 32 38 33 2d 34 37 37 35 34 35 33 63 61 62 63 63 } 	condition:
		((#a_81_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}