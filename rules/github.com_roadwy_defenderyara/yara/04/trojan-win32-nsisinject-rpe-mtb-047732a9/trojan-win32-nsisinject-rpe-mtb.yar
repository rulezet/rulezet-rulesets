rule Trojan_Win32_NSISInject_RPE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {32 30 2e 32 35 34 2e 35 33 2e 34 37 2f 62 72 75 6d 65 2e 70 68 70 } 		$a_81_1 = {32 30 2e 32 33 34 2e 32 33 31 2e 31 31 34 2f 6d 78 2f 6a 35 37 62 35 67 39 73 38 74 72 35 38 63 77 6d 30 70 70 70 } 		$a_81_2 = {70 69 66 65 61 69 7a 67 6a 63 2e 68 64 61 } 		$a_81_3 = {65 36 37 34 34 62 34 36 6c 66 39 34 62 38 36 72 65 31 63 6f 6f 6f } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}