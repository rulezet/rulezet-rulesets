rule Trojan_Win32_Gozi_GM_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 45 ef 83 e8 ?? 99 03 05 [0-04] 13 15 [0-04] a2 [0-04] 0f b7 05 [0-04] 3d [0-04] 90 18 0f b6 45 ?? 83 e8 ?? 99 03 45 ?? 13 55 ?? a3 [0-04] 89 15 [0-04] a1 [0-04] 05 [0-04] a3 [0-04] 8b 0d [0-04] 03 4d ?? 8b 15 [0-04] 89 91 [0-04] a1 [0-04] 83 e8 ?? 33 c9 2b 05 [0-04] 1b 0d [0-04] 88 45 ?? e9 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}