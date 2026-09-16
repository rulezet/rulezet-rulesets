rule Trojan_Win32_Guloader_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 0c 1e 81 [0-20] 90 13 [0-20] 81 f1 [0-20] 90 13 [0-10] 31 0c 1f [0-20] 81 c3 [0-10] 90 13 [0-10] 81 eb [0-10] 90 13 [0-20] 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}