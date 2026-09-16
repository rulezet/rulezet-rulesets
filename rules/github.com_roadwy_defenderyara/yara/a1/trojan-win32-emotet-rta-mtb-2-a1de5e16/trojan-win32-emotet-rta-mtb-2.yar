rule Trojan_Win32_Emotet_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 61 68 6b 67 6b 78 6b 64 72 6f 6b 6c 6a } 		$a_01_1 = {62 6b 61 7a 7a 73 64 70 63 74 70 6d 79 72 61 } 		$a_01_2 = {65 77 6f 79 70 77 73 62 64 61 70 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}