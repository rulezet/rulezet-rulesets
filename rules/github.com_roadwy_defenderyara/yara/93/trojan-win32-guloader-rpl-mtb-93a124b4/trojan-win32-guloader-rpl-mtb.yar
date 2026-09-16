rule Trojan_Win32_Guloader_RPL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d9 d0 33 04 32 [0-20] 35 [0-20] 90 13 [0-10] 8b 1c 24 [0-20] 01 04 33 [0-20] 83 ee 04 0f 8d ?? ?? ff ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}