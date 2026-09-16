rule Trojan_Win64_IcedID_SD_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8d 04 16 83 e2 ?? 41 83 e0 ?? 8a 44 94 ?? 42 02 44 84 ?? 41 32 04 3b 41 88 04 0b 4c 03 de 42 8b 4c 84 ?? 8b 44 94 ?? 83 e1 ?? d3 c8 ff c0 89 44 94 } 		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}