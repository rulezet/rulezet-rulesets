rule Trojan_BAT_Bladabindi_NV_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c } 		$a_01_1 = {08 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 0d 1b } 		$a_01_2 = {08 6e 17 6a d6 20 ff 00 00 00 6a 5f b8 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}