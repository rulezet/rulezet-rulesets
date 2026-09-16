rule Trojan_Win64_CryptInject_MB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 c1 e9 08 48 69 c1 ?? ?? ?? ?? 49 8b c8 48 2b c8 41 8a 04 18 32 04 11 41 88 04 18 49 ff c0 49 83 f8 71 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}