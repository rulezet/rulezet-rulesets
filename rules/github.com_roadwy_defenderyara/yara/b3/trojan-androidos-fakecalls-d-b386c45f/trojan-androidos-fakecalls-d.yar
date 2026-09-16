rule Trojan_AndroidOS_Fakecalls_D{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 5f 68 75 68 75 } 		$a_01_1 = {75 70 6c 6f 61 64 53 4d 53 46 69 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}