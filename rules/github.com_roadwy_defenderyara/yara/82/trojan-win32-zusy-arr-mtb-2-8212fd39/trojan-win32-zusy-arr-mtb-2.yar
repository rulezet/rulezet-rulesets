rule Trojan_Win32_Zusy_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 0f af 06 83 c0 ?? 8b cb 50 6a } 		$a_01_1 = {0f af d0 03 d7 89 14 81 8b 0e 40 3b c1 } 	condition:
		((#a_03_0  & 1)*7+(#a_01_1  & 1)*13) >=20
 
}