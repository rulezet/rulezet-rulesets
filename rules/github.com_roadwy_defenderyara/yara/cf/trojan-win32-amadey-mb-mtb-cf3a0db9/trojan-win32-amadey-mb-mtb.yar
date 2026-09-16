rule Trojan_Win32_Amadey_MB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 6a 01 6a 00 6a 03 6a 00 6a 00 8d 45 08 89 8d 94 fb ff ff 0f 43 45 08 6a 50 50 51 ff 15 } 		$a_01_1 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}