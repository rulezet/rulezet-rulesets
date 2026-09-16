rule Trojan_AndroidOS_Smsthief_F{
	meta:
		description = "Trojan:AndroidOS/Smsthief.F,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 69 6e 64 4e 6f 64 65 73 42 79 54 65 78 74 76 32 } 		$a_01_1 = {5f 77 69 66 69 70 6f 6c 63 5f 6d 65 74 68 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}