rule Trojan_AndroidOS_Piom_V{
	meta:
		description = "Trojan:AndroidOS/Piom.V,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 51 41 41 41 41 55 41 41 41 42 55 56 6b 64 44 56 46 6c 58 64 46 4a 46 58 6c 56 63 52 55 68 6a 53 30 64 55 55 46 4d } 		$a_01_1 = {44 67 41 41 41 41 55 41 41 41 42 51 52 6b 46 79 58 56 5a 51 52 6e 31 65 56 6b 64 51 51 77 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}