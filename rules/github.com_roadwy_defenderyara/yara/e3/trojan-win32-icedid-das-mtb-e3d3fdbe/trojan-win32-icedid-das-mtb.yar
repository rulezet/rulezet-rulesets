rule Trojan_Win32_IcedId_DAS_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2a cb 02 c1 8b 4c 24 18 89 39 8b 7c 24 0c 83 c7 04 89 7c 24 0c 81 ff 07 12 00 00 0f } 		$a_01_1 = {44 65 73 65 72 74 70 69 63 6b } 		$a_01_2 = {52 75 6e 62 6f 6f 6b } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}