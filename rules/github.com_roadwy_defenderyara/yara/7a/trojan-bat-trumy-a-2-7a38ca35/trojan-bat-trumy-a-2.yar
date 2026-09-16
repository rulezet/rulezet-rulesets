rule Trojan_BAT_Trumy_A_2{
	meta:
		description = "Trojan:BAT/Trumy.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {2f 70 72 6f 67 72 61 6d 2e 70 68 70 } 		$a_80_1 = {67 65 74 3d 63 68 72 6f 6d 65 } 		$a_80_2 = {5c 63 68 72 6f 6d 65 2e 64 6c 6c } 		$a_80_3 = {65 6b 6c 65 6e 74 69 } 		$a_80_4 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}