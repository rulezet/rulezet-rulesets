rule Trojan_Win32_Zusy_BAC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 10 33 ca 8b 45 08 03 45 98 0f b6 30 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}