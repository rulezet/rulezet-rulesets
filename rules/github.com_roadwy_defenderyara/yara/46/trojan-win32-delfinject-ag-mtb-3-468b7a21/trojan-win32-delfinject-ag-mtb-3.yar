rule Trojan_Win32_DelfInject_AG_MTB_3{
	meta:
		description = "Trojan:Win32/DelfInject.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {5a 63 65 64 6d 6a 6e 5a } 		$a_80_1 = {57 6e 64 50 72 6f 63 50 74 72 25 2e 38 58 25 2e 38 58 } 		$a_80_2 = {77 69 6e 68 74 74 70 } 		$a_00_3 = {44 00 45 00 53 00 54 00 41 00 04 00 41 00 4b 00 41 00 4e } 		$a_00_4 = {71 49 44 41 54 78 9c ed 9d 69 83 82 2a 14 86 c5 b6 a9 6c 9b b4 a9 b1 29 } 		$a_80_5 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } 	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}