rule Trojan_Win32_Zusy_BAC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 62 00 00 00 f3 a4 8d 85 62 ff ff ff 89 04 24 e8 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}