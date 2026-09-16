rule Trojan_BAT_AsyncRAT_PDJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 02 73 14 00 00 0a 0c 08 07 16 73 15 00 00 0a 0d 73 16 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 } 		$a_01_1 = {06 18 6f 10 00 00 0a 06 06 6f 11 00 00 0a 06 6f 12 00 00 0a 6f 13 00 00 0a 0b 02 73 14 00 00 0a 0c 08 07 16 73 15 00 00 0a 0d 73 16 00 00 0a 13 04 09 11 04 6f 17 00 00 0a 11 04 6f 18 00 00 0a 13 05 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}