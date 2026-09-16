rule Trojan_BAT_PureLogStealer_NP_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f fe 0e 31 00 fe 0c 30 00 1a 64 fe 0c 31 00 1a 62 60 fe 0c 28 00 61 fe 0e 30 00 fe 0c 29 00 1d 62 fe 0c 29 00 1f 19 64 60 fe 0e 29 00 fe 0c 2a 00 76 6c } 		$a_01_1 = {fe 0c 2a 00 76 6c 5b fe 0c 2a 00 76 6c 58 6d fe 0e 32 00 20 37 ff ff ff 6a fe 0c 28 00 6e 59 6d fe 0c 32 00 58 6e 20 37 ff ff ff 6a 58 6d fe 0e 2a 00 } 		$a_01_2 = {53 65 74 70 74 32 36 26 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}