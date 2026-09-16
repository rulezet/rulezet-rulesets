rule Trojan_Win32_CryptInject_SD_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.SD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 6d 65 5c 41 75 74 6f 73 74 61 72 74 5c } 		$a_01_1 = {5c 65 78 63 2e 65 78 65 } 		$a_01_2 = {57 69 6e 33 32 2e 63 72 41 63 6b 65 72 2e 41 } 		$a_01_3 = {79 6f 75 70 6f 72 6e 2e 63 6f 6d } 		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}