rule Trojan_Win64_CryptoStealBTC{
	meta:
		description = "Trojan:Win64/CryptoStealBTC,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {31 00 37 00 63 00 39 00 59 00 37 00 53 00 67 00 58 00 39 00 74 00 68 00 64 00 61 00 77 00 79 00 55 00 79 00 48 00 59 00 79 00 45 00 42 00 65 00 41 00 37 00 45 00 7a 00 34 00 32 00 72 00 4e 00 57 00 67 00 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}