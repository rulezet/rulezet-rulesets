rule Trojan_Win32_Zenpak_BX_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 cd 02 2d } 		$a_01_1 = {0f b6 c4 5d c3 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}