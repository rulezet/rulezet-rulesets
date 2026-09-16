rule Trojan_Win32_Guloader_RPO_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 1c 10 83 ff 2e 83 fa 43 9b db e2 66 0f fa fa db e3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}