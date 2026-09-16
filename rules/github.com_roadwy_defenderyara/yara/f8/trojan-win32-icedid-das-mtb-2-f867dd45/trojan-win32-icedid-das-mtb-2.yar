rule Trojan_Win32_IcedId_DAS_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 6a 01 53 8d 45 ?? 53 50 89 5d 0c ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 53 8d 45 90 1b 00 53 50 ff 15 90 1b 01 85 c0 } 		$a_81_1 = {45 6d 31 4f 37 63 63 73 44 48 41 51 45 55 6a } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}