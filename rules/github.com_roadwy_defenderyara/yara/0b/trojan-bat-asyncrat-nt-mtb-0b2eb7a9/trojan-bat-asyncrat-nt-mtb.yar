rule Trojan_BAT_AsyncRAT_NT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 9a 28 1e 00 00 0a 6f ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 2c 04 17 0d de 5d 08 17 58 0c 08 06 8e } 		$a_01_1 = {43 73 68 61 72 70 50 75 72 65 46 69 6e 64 65 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}