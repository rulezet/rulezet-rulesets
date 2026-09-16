rule Trojan_Win32_Vidar_RZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 83 c4 0c 34 74 8b cb 04 59 88 04 37 6a 6f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}