rule Trojan_Win32_Guloader_RPQ_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 66 31 0c 1f d8 e4 d8 d9 eb 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}