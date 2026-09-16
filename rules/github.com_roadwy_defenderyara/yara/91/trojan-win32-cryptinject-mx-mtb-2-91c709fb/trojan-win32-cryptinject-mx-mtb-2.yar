rule Trojan_Win32_Cryptinject_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Cryptinject.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 81 6c 24 ?? 52 ef 6f 62 2d f3 32 05 00 81 6c 24 ?? 68 19 2a 14 81 44 24 ?? be 08 9a 76 8b 44 24 } 		$a_02_1 = {8b 54 24 20 c1 ea 05 03 54 24 38 89 54 24 ?? 3d 31 09 00 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}