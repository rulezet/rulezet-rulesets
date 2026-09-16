rule Trojan_AndroidOS_Piom_A_3{
	meta:
		description = "Trojan:AndroidOS/Piom.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 37 7a 48 6c 4d 53 4e 5a 6d 48 45 67 31 42 6c 63 6d 31 70 63 33 4e 70 62 32 35 6d 59 63 53 44 59 57 58 45 6a 51 3d 3d } 		$a_01_1 = {5a 4d 65 57 78 49 6c 6d 59 63 53 44 5a 32 56 30 55 47 46 30 61 47 5a 68 78 49 50 46 71 38 65 63 78 49 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}