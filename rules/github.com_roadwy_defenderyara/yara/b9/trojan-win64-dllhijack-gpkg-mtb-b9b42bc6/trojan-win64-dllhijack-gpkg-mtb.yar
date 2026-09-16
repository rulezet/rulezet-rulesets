rule Trojan_Win64_DllHijack_GPKG_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.GPKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 24 8b 44 24 24 35 ef be ad de 89 44 24 28 8b 44 24 28 83 c0 ?? 89 44 24 20 8b 44 24 20 c1 e0 ?? 89 44 24 24 8b 44 24 24 } 		$a_81_1 = {73 69 64 65 6c 6f 61 64 } 	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*2) >=7
 
}