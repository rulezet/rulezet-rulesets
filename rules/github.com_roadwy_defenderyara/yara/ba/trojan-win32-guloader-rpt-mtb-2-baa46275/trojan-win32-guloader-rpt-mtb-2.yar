rule Trojan_Win32_Guloader_RPT_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 2c 1a 90 9b 31 2c 18 9b 90 81 34 18 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}