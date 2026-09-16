rule Trojan_Win32_CryptInject_BH_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BH!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 20 61 72 65 20 66 75 63 6b 69 6e 67 20 41 56 20 76 65 6e 64 6f 72 73 21 } 		$a_01_1 = {6b 69 63 6b 69 6e 67 20 67 75 79 73 } 		$a_01_2 = {59 6f 75 20 61 72 65 20 6d 79 20 73 75 6e 73 68 69 6e 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}