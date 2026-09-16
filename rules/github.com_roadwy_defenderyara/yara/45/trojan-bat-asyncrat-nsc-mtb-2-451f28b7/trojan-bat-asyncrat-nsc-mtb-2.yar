rule Trojan_BAT_AsyncRAT_NSC_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.NSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 88 00 00 0a 7e ?? 00 00 04 07 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 7e ?? 00 00 04 2c 08 02 11 04 28 ?? 00 00 06 11 04 13 05 de 06 } 		$a_01_1 = {4e 61 73 68 77 69 6c 6c 65 } 		$a_01_2 = {4e 65 74 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}