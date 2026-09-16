rule Trojan_Win32_ICLoader_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c6 04 57 8d 4d f8 56 8b 75 08 51 50 89 45 e0 ff 56 70 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}