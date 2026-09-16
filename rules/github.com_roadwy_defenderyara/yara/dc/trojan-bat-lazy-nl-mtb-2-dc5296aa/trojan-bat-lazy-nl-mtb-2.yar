rule Trojan_BAT_Lazy_NL_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 7b 00 00 0a 02 6f ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 06 6f ?? 00 00 0a 28 28 00 00 06 } 		$a_01_1 = {4b 65 79 41 75 74 68 20 4c 6f 61 64 65 72 20 57 69 6e 66 6f 72 6d 20 45 78 61 6d 70 6c 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}