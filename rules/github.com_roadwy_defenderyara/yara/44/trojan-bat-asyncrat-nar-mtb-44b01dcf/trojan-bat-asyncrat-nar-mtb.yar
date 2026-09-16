rule Trojan_BAT_AsyncRAT_NAR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f f8 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 } 		$a_01_1 = {41 73 79 6e 63 52 41 54 2d 43 6c 69 65 6e 74 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}