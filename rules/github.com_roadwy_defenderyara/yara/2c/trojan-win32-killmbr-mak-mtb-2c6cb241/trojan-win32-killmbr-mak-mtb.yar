rule Trojan_Win32_KillMBR_MAK_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 		$a_80_1 = {4e 4f 20 45 53 43 41 50 45 } 		$a_80_2 = {64 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 6b 69 6c 6c 20 74 68 65 20 70 72 6f 63 65 73 73 } 		$a_80_3 = {50 61 79 6c 6f 61 64 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}