rule Trojan_Win32_Gozi_GR_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 38 8b 44 24 ?? 2b c3 83 c0 ?? 03 c2 3b 05 [0-04] 90 18 8d 58 a2 81 c7 [0-04] 8b 44 24 ?? 03 de 89 3d [0-04] 33 c9 89 38 83 c0 04 8b 3d [0-04] 89 44 24 ?? 8d 57 ?? 03 d3 ff 4c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}