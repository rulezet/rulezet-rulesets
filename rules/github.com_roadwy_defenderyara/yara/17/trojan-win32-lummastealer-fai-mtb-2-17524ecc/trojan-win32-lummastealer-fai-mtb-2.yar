rule Trojan_Win32_LummaStealer_FAI_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.FAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 18 8b 44 24 40 33 c8 83 c0 02 f7 74 24 5c 0f b6 04 2a 03 44 24 28 03 c1 0f b6 d3 03 d0 8b 44 24 38 81 e2 ff 03 00 00 89 54 24 28 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}