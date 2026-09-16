rule Trojan_O97M_Donoff_SBR_MSR{
	meta:
		description = "Trojan:O97M/Donoff.SBR!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 65 72 25 75 25 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*5) >=5
 
}