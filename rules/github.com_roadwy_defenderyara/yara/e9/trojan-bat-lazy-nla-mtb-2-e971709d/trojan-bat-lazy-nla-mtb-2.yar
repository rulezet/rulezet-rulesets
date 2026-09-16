rule Trojan_BAT_Lazy_NLA_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 18 58 13 04 38 ?? 00 00 00 11 03 11 04 18 5b 11 06 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 38 d8 ff ff ff } 		$a_01_1 = {6e 6f 64 65 66 66 65 6e 64 65 72 } 		$a_01_2 = {4b 44 45 20 53 6f 66 74 77 61 72 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}