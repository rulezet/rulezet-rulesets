rule Trojan_Win32_Tnega_MR_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 03 c8 0f b6 c1 8b 0d [0-04] 0f b6 84 05 [0-04] 30 04 19 43 3b 9d [0-04] 72 90 09 1e 00 0f b6 84 3d [0-04] 88 84 35 [0-04] 88 94 3d [0-04] 0f b6 8c 35 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}