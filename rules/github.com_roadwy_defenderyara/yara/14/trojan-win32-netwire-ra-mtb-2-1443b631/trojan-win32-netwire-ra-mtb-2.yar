rule Trojan_Win32_NetWire_RA_MTB_2{
	meta:
		description = "Trojan:Win32/NetWire.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4c 6f 67 73 5c } 		$a_80_1 = {48 6f 73 74 49 64 2d } 		$a_80_2 = {48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4e 65 74 57 69 72 65 } 		$a_80_3 = {49 6e 73 74 61 6c 6c 20 44 61 74 65 } 		$a_80_4 = {44 41 52 4b 45 59 45 44 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*3+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=7
 
}