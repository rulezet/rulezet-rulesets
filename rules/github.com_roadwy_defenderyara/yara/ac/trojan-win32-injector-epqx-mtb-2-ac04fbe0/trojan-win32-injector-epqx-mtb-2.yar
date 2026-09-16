rule Trojan_Win32_Injector_EPQX_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.EPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {ff 34 0b 5a 81 f2 ?? ?? ?? ?? 09 14 0f 83 c1 fc } 		$a_81_1 = {55 74 69 6c 67 69 76 65 6c 69 67 68 65 64 65 72 6e 65 73 31 } 		$a_81_2 = {53 61 6d 6d 65 6e 74 72 79 6b 6b 65 73 32 } 		$a_81_3 = {54 65 6d 70 6f 72 69 73 65 72 73 34 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}