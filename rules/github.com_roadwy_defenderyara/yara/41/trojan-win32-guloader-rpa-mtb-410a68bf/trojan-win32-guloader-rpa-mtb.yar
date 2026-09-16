rule Trojan_Win32_GuLoader_RPA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 34 32 0f [0-10] 90 13 [0-10] 90 13 [0-10] 90 13 [0-10] 81 34 24 [0-10] 90 13 [0-10] 90 13 [0-10] 90 13 [0-10] 8f 04 30 [0-10] 90 13 [0-10] 90 13 [0-20] 90 13 [0-10] 90 13 [0-10] 83 de [0-10] 90 13 [0-10] 90 13 [0-10] 83 d6 [0-10] 90 13 [0-10] 0f 8d } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}