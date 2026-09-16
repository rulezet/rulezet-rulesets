rule Trojan_BAT_Quasar_NQQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 03 17 11 04 58 91 11 04 1e 5a 1f 1f 5f 62 58 0d 11 04 17 58 13 04 11 04 1a 3f e1 ff ff ff } 		$a_01_1 = {62 79 63 72 70 66 6d 61 6e 68 64 71 75 65 72 70 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}