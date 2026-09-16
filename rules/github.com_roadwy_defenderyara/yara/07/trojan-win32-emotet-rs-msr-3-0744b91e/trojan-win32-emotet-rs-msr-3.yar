rule Trojan_Win32_Emotet_RS_MSR_3{
	meta:
		description = "Trojan:Win32/Emotet.RS!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 3a 5c 43 7a 78 61 73 64 2e 6e 6d 6a 6b } 		$a_01_1 = {64 64 65 65 78 65 63 } 		$a_01_2 = {5b 70 72 69 6e 74 74 6f 28 22 25 31 22 2c 22 25 32 22 2c 22 25 33 22 2c 22 25 34 22 29 5d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}