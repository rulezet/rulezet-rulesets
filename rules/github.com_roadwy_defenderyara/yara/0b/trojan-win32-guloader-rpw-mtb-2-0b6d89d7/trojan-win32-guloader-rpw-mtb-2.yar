rule Trojan_Win32_Guloader_RPW_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 3c 01 d8 c1 d9 f1 eb 19 9e 76 d4 70 93 93 93 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}