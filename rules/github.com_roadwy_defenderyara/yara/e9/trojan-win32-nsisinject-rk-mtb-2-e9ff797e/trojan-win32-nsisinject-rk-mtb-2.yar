rule Trojan_Win32_NSISInject_RK_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 6b c0 14 01 c1 8b 45 10 2b 45 f4 83 e8 01 6b c0 14 89 14 24 } 		$a_01_1 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}