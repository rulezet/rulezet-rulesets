rule Trojan_Linux_LinkPro_E{
	meta:
		description = "Trojan:Linux/LinkPro.E,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {5b 4b 4e 4f 43 4b 2d 53 45 54 5d } 		$a_00_1 = {5b 4b 4e 4f 43 4b 5d } 		$a_00_2 = {5b 44 42 47 2d 58 44 50 5d } 		$a_00_3 = {5b 44 42 47 2d 4b 4e 4f 43 4b 5d } 		$a_00_4 = {5b 54 43 2d 4d 49 53 53 5d } 		$a_00_5 = {5b 45 58 50 49 52 45 44 5d } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}