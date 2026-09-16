rule Trojan_BAT_Kryptik_SK_eml{
	meta:
		description = "Trojan:BAT/Kryptik.SK!eml,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 2e 70 64 62 90 0a 58 00 43 3a 5c 55 73 65 72 73 5c 53 61 6b 6f 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 5c 4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 5c 6f 62 6a 5c 44 65 62 75 67 } 		$a_00_1 = {63 3a 5c 74 65 6d 70 5c 41 73 73 65 6d 62 6c 79 2e 65 78 65 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}