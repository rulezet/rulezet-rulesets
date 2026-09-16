rule Trojan_Win32_Vidar_SPFD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d dc 30 04 31 83 ff 0f } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}