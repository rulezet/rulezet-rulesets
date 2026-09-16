rule Trojan_Win32_Nanocore_ST_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ad 85 c0 74 90 01 01 03 04 24 81 38 55 8b ec 83 75 ef 81 78 04 ec 0c 56 8d 75 e6 } 		$a_02_1 = {8b 04 0a 01 f3 [0-04] 0f ef c0 [0-04] 0f ef c9 0f 6e c0 0f 6e 0b 0f ef c1 [0-04] 51 0f 7e c1 88 c8 [0-04] 59 29 f3 [0-04] 83 c3 01 75 ?? [0-04] 89 fb [0-04] [0-04] 89 04 0a [0-04] 83 c1 01 75 c9 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}