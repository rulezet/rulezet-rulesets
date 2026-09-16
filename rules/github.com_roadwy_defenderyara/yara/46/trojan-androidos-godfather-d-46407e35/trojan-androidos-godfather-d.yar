rule Trojan_AndroidOS_Godfather_D{
	meta:
		description = "Trojan:AndroidOS/Godfather.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 5f 41 50 50 4c 4f 47 53 } 		$a_01_1 = {73 65 6e 64 53 6d 73 74 6f 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}