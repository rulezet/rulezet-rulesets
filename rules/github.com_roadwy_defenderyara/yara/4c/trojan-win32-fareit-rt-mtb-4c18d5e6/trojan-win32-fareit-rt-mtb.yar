rule Trojan_Win32_Fareit_RT_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {81 f7 c7 bb ce 37 83 ff 6f 81 ff aa 00 00 00 9b db e3 66 0f 62 c8 dd c0 66 0f db e7 66 } 		$a_03_1 = {89 3b 81 fe a3 00 00 00 3d fc 00 00 00 c7 44 24 ?? 9d 00 00 00 83 fa 62 66 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}