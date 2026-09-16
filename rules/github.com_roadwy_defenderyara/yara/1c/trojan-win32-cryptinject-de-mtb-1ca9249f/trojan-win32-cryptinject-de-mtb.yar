rule Trojan_Win32_CryptInject_DE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 33 4d fc 89 4d fc 8b 55 08 83 c2 01 89 55 08 c7 45 f8 00 00 00 00 eb 09 } 		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}