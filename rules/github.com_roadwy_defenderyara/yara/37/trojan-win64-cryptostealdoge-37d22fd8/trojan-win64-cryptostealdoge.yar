rule Trojan_Win64_CryptoStealDOGE{
	meta:
		description = "Trojan:Win64/CryptoStealDOGE,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {44 00 39 00 58 00 71 00 38 00 53 00 4a 00 4b 00 36 00 79 00 31 00 4d 00 47 00 35 00 57 00 74 00 38 00 41 00 71 00 61 00 72 00 69 00 64 00 6e 00 46 00 46 00 6d 00 42 00 69 00 63 00 57 00 62 00 67 00 77 00 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}