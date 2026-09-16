rule Trojan_Win32_IcedId_EC_MTB{
	meta:
		description = "Trojan:Win32/IcedId.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c0 0e 66 89 44 24 30 3a db 74 d9 66 89 44 24 36 b8 1b 00 00 00 e9 1c 01 00 00 48 83 ec 68 48 c7 44 24 20 00 00 00 00 3a d2 74 00 48 c7 44 24 28 00 00 00 00 b8 23 00 00 00 3a ed 74 c2 } 		$a_01_1 = {66 75 61 64 73 79 67 75 61 73 67 64 75 68 61 69 73 75 64 6a 79 75 61 67 73 64 75 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}