rule Trojan_Win32_Fragtor_AFG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 06 03 05 88 65 41 00 6a 00 6a 04 68 88 65 41 00 50 57 ff d3 83 c6 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}