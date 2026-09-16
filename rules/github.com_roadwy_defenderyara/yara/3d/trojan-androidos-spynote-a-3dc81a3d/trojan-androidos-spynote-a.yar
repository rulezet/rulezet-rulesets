rule Trojan_AndroidOS_Spynote_A{
	meta:
		description = "Trojan:AndroidOS/Spynote.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 48 68 55 65 46 51 3d } 		$a_01_1 = {55 33 52 68 63 6e 52 4f 5a 58 64 54 59 32 46 75 } 		$a_01_2 = {70 61 73 73 67 6d 61 6c } 		$a_01_3 = {6e 65 65 64 64 6f 6e 65 } 		$a_01_4 = {52 65 63 6f 76 65 72 67 6d 61 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}