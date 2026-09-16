rule Trojan_Linux_Finspy_A_{
	meta:
		description = "Trojan:Linux/Finspy.A!!Finspy.A,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {a5 aa ca a6 54 5a ?? ?? 5a a5 0a } 		$a_01_1 = {7f 0d 45 4c 46 01 02 c2 14 68 03 05 0e } 		$a_01_2 = {7f 07 45 4c 46 02 01 1e 15 01 8e 03 0e } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}