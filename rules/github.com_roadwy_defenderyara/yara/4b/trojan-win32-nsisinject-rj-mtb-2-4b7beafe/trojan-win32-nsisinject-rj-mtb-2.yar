rule Trojan_Win32_NSISInject_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d8 59 59 85 db 74 21 8b f3 2b f7 d1 fe 03 f6 56 57 8b 7d f4 57 } 		$a_01_1 = {0f b7 16 66 85 d2 74 11 83 fa 22 74 05 66 89 14 47 40 83 c6 02 3b c1 7c e7 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}