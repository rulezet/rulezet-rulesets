rule Trojan_Win32_Hancitor_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Hancitor.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c1 80 eb [0-01] 89 44 24 [0-01] 03 c6 8b 74 24 [0-01] 03 d0 0f b7 c2 02 da 89 44 24 [0-01] 8b 44 24 [0-01] 05 [0-04] 66 89 15 [0-04] 89 06 83 c6 04 83 6c 24 [0-01] 01 a3 [0-04] 8b 44 24 [0-01] 89 74 24 [0-01] 0f b7 f0 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}