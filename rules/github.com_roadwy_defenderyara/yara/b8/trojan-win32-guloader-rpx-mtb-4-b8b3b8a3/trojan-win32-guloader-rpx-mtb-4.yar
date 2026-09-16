rule Trojan_Win32_Guloader_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 1c 10 d9 f2 dd e1 0f 6f df 0f e8 fc eb 2b 26 0b 1e 01 26 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}