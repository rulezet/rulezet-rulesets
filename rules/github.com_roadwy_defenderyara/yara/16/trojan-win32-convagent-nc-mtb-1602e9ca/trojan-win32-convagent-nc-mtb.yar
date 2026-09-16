rule Trojan_Win32_Convagent_NC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 f4 8a 85 ee fa ff ff c6 85 fc fe ff ff 20 84 c0 74 2e 8d 9d ef fa ff ff 0f b6 c8 0f b6 03 3b c8 77 16 2b c1 } 		$a_01_1 = {44 00 69 00 68 00 79 00 62 00 72 00 69 00 64 00 73 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}