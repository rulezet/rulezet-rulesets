rule Trojan_Win32_Guloader_VB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 34 0a 81 f6 [0-05] 89 34 08 83 e9 [0-05] 7d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}