rule Trojan_Win32_SmokeLoader_DG_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 37 89 4c 24 20 8b 4c 24 1c 8b d6 d3 ea 8b 4c 24 38 8d 44 24 14 c7 05 [0-04] ee 3d ea f4 89 54 24 14 e8 [0-04] 8b 44 24 20 31 44 24 10 81 3d [0-04] e6 09 00 00 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}