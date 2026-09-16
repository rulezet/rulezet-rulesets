rule Trojan_Win32_SmokeLoader_DA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 4c 24 1c 8b 54 24 18 d3 ea 8b cd 8d 44 24 28 89 54 24 28 e8 [0-04] 8b 44 24 20 31 44 24 10 81 3d [0-04] 21 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}