rule Trojan_Win32_Gozi_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {f2 0f b6 45 ?? 99 03 c1 13 d6 88 45 ?? 8b 15 [0-04] 81 c2 [0-04] 89 15 [0-04] a1 [0-04] 03 45 ?? 8b 0d [0-04] 89 88 [0-04] 0f b7 55 ?? a1 [0-04] 8d 8c 10 [0-04] 0f b6 55 ?? 03 ca 0f b6 45 ?? 03 c1 88 45 ?? e9 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}