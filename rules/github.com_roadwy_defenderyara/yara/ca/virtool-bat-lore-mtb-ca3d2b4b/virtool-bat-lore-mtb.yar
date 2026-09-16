rule VirTool_BAT_Lore_MTB{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6e 61 6b 65 4c 69 62 2e 64 6c 6c } 		$a_01_1 = {53 6e 61 6b 65 2e 53 49 47 44 55 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } 		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}