rule Trojan_Win32_NSISInject_RX_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 61 6e 64 6c 67 65 6b 6c 69 6e 69 6b 6b 65 72 32 31 32 2e 6d 61 72 } 		$a_01_1 = {43 3a 5c 54 45 4d 50 5c 6f 76 65 72 6d 61 6e 64 65 64 65 5c 4d 65 74 72 61 6e } 		$a_01_2 = {53 59 53 54 45 4d 33 32 5c 65 6e 65 72 67 65 74 69 73 6b 65 73 5c 50 68 79 73 69 63 69 61 6e 65 72 32 32 33 2e 6c 6e 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}