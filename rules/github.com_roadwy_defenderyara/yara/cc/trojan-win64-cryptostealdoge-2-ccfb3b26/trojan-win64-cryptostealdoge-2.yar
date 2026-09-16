rule Trojan_Win64_CryptoStealDOGE_2{
	meta:
		description = "Trojan:Win64/CryptoStealDOGE,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {44 00 42 00 4b 00 51 00 4a 00 6d 00 6b 00 79 00 6b 00 54 00 74 00 6e 00 31 00 6a 00 37 00 42 00 34 00 64 00 6e 00 75 00 33 00 74 00 50 00 45 00 74 00 35 00 4a 00 7a 00 78 00 55 00 33 00 4e 00 67 00 4e 00 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}