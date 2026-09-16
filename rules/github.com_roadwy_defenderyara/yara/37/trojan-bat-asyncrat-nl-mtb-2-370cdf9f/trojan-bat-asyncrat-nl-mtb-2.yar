rule Trojan_BAT_AsyncRAT_NL_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 20 19 00 00 00 38 59 f2 ff ff 00 02 7b 1f 00 00 04 20 93 ?? ?? ?? 20 01 00 00 00 63 20 9d ?? ?? ?? 61 7e 47 01 00 04 7b 2e 01 00 04 61 7e ae 03 00 04 } 		$a_03_1 = {20 75 00 00 00 fe 0e 01 00 38 9b fb ff ff 00 02 11 00 20 82 ?? ?? ?? 20 ac d2 88 c5 61 20 9c ef 18 25 61 7e 47 ?? ?? ?? 7b 7c 01 00 04 61 7e ae 03 00 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}