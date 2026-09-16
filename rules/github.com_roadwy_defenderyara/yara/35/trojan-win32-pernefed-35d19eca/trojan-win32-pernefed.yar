rule Trojan_Win32_Pernefed{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } 		$a_02_1 = {50 44 32 30 ?? ?? 4d 6f 6e 69 74 6f 72 00 00 00 70 64 2e 64 6c 6c } 		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 70 64 2e 64 6c 6c } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}