rule Trojan_BAT_Tedy_NTY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 07 1e 02 8e 69 59 02 8e 69 28 ?? 00 00 0a 07 16 07 8e 69 1a 5b 1a 5a 03 } 		$a_01_1 = {4e 6f 76 61 6c 69 6e 65 20 49 6e 73 74 61 6c 6c 65 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}