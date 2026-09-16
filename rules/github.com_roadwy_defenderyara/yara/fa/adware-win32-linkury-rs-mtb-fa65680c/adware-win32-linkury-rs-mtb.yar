rule Adware_Win32_Linkury_RS_MTB{
	meta:
		description = "Adware:Win32/Linkury.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {4c 69 6e 6b 75 72 79 2e 52 65 73 6f 75 72 63 65 73 2e 43 68 72 6f 6d 65 4e 65 77 54 61 62 2e 42 6c 61 63 6b 4c 69 73 74 4d 61 6e 61 67 65 72 3a 3a 42 6c 61 63 6b 4c 69 73 74 4d 61 6e 61 67 65 72 3a 54 72 75 65 3a } 	condition:
		((#a_80_0  & 1)*1) >=1
 
}