rule Trojan_Win32_Injector_RPW_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c2 02 00 00 00 [0-10] 39 ca 7e 90 09 30 00 [0-20] 8a 1a [0-10] 88 1e [0-10] 46 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}