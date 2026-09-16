rule Trojan_BAT_Injector_AH_MTB_2{
	meta:
		description = "Trojan:BAT/Injector.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 36 1e 1f 2e 9c 11 36 1f 09 1f 64 9c 11 36 1f 0a 1f 6c 9c 11 36 1f 0b 1f 6c 9c 11 36 } 		$a_03_1 = {11 2a 20 00 30 00 00 1a 6f ?? ?? ?? 06 13 24 11 24 16 33 06 73 ?? ?? ?? 0a 7a 11 1c 12 09 7b ?? ?? ?? 04 11 24 04 11 29 12 0c 6f ?? ?? ?? 06 } 	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}