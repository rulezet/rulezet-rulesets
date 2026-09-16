rule Trojan_AndroidOS_Smsthief_D{
	meta:
		description = "Trojan:AndroidOS/Smsthief.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 75 6e 74 20 33 30 25 3a 20 28 69 6c 6f 76 65 72 65 64 39 39 29 20 52 4d } 		$a_01_1 = {3f 70 61 73 73 3d 61 70 70 31 36 38 26 63 6d 64 3d 73 6d 73 26 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}