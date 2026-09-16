rule Trojan_Win32_DelfInject_AG_MTB_2{
	meta:
		description = "Trojan:Win32/DelfInject.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } 		$a_00_1 = {46 00 52 00 45 00 52 00 05 00 4d 00 54 00 4f 00 47 00 4f } 		$a_00_2 = {44 6f 63 6b 53 69 74 65 } 		$a_80_3 = {44 65 43 6f 64 65 72 } 		$a_80_4 = {4b 69 6c 6c 54 69 6d 65 72 } 		$a_80_5 = {4c 6f 61 64 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 41 } 	condition:
		((#a_80_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}