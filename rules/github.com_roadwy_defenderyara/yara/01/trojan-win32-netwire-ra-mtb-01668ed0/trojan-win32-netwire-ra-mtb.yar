rule Trojan_Win32_NetWire_RA_MTB{
	meta:
		description = "Trojan:Win32/NetWire.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {88 88 28 32 9f 00 40 3b f8 77 f5 } 		$a_01_1 = {33 0c 83 8b 55 08 8b 45 f8 89 0c 82 } 		$a_01_2 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } 		$a_01_3 = {69 70 63 6f 6e 66 69 67 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}