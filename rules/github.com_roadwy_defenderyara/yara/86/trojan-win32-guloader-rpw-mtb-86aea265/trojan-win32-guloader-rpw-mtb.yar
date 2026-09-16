rule Trojan_Win32_Guloader_RPW_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 78 38 30 30 30 30 30 30 30 00 56 69 72 74 75 00 61 6c 41 6c 00 03 82 80 00 36 30 00 69 6c 65 00 6c 6f 63 45 00 37 31 30 00 31 33 31 31 30 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}