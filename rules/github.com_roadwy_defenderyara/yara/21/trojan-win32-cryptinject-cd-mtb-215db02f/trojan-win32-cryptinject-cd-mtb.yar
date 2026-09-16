rule Trojan_Win32_CryptInject_CD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {2f 73 6f 63 68 76 73 74 2e 62 61 74 } 		$a_81_1 = {48 45 42 45 43 41 40 43 48 49 4e 41 2e 43 4f 4d } 		$a_81_2 = {44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}