rule Trojan_Win32_SmokeLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 14 33 83 ff 0f 75 4d 6a 00 6a 00 6a 00 ff d5 6a 2e 8d 44 24 10 6a 00 50 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}