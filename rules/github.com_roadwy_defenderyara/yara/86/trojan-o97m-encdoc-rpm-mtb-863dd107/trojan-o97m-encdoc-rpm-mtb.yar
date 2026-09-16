rule Trojan_O97M_EncDoc_RPM_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.RPM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 73 74 72 72 65 76 65 72 73 65 28 22 74 78 74 2e 63 6e 65 2f 38 38 2f 35 34 2e 31 30 31 2e 32 33 31 2e 38 33 2f 2f 3a 70 74 74 68 22 29 } 		$a_01_1 = {52 65 70 6c 61 63 65 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}