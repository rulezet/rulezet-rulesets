rule Trojan_Win32_CryptInject_AG_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 69 73 65 5c 57 69 6e 64 6f 77 5c 70 6f 73 69 74 69 6f 6e 5c 43 68 61 72 61 63 74 65 72 5c 6f 70 70 6f 73 69 74 65 5c 4d 69 73 73 5c 6c 61 77 43 6f 6d 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}