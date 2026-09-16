rule Trojan_BAT_Kryptik_FI_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 04 00 00 "
		
	strings :
		$a_00_0 = {11 04 13 05 11 05 1f 41 32 06 11 05 1f 4d } 		$a_00_1 = {11 05 1f 4e 32 06 11 05 1f 5a 31 14 11 05 1f } 		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=24
 
}