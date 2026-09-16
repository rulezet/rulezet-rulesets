rule Trojan_Win32_Zusy_AZU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 40 c7 44 24 4c 06 00 00 00 8d 05 c3 ab 4c 00 89 44 24 48 c7 44 24 54 08 00 00 00 8d 05 db ae 4c 00 89 44 24 50 8b 44 24 1c 89 44 24 5c 89 54 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}