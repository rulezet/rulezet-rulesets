rule Trojan_Win32_Stelega_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Stelega.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 ee f0 85 07 86 e8 ?? ?? ?? ?? 42 31 19 89 d2 01 d6 41 09 d2 39 c1 75 } 		$a_03_1 = {bb b2 c9 4e 00 40 e8 ?? ?? ?? ?? b8 14 14 3e 71 31 1e 21 c0 49 81 c6 01 00 00 00 21 c1 39 fe 75 df } 		$a_00_2 = {81 ef 47 82 38 7e 31 02 09 cb 89 cb 42 49 f7 d1 81 c6 01 00 00 00 } 		$a_00_3 = {81 e9 bc 68 1d 4f 01 d9 31 30 b9 a5 95 dc d9 bf c8 c8 fe 14 29 df 40 01 cf 81 c1 af 07 21 4c } 		$a_00_4 = {89 ca 01 d2 81 c2 01 00 00 00 31 3b 81 ea 01 00 00 00 81 e9 56 51 f4 b4 01 f6 43 21 f2 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=1
 
}