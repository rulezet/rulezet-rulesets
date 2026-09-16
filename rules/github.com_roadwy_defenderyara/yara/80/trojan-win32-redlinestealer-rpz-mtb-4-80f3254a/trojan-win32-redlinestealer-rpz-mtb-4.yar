rule Trojan_Win32_RedLineStealer_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 04 8d 4d dc 51 8b 8b a4 00 00 00 83 c1 08 51 ff 75 cc ff d0 6a 40 68 00 30 00 00 ff b7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}