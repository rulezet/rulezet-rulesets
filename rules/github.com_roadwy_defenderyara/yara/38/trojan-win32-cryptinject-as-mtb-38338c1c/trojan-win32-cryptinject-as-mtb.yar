rule Trojan_Win32_CryptInject_AS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 5c 00 2e 00 5c 00 61 00 76 00 67 00 53 00 50 00 5f 00 4f 00 70 00 65 00 6e 00 } 		$a_02_1 = {31 ca 59 8a 0c 10 5a 84 c9 75 12 8b 0d ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 03 c8 03 cf 30 19 39 15 ?? ?? ?? ?? 76 03 40 eb 01 cb } 		$a_00_2 = {03 d9 03 c8 46 8a 1c 03 88 1c 39 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}