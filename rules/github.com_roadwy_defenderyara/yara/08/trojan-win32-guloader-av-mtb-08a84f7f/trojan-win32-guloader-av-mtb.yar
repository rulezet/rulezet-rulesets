rule Trojan_Win32_Guloader_AV_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c2 f5 94 08 00 89 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}