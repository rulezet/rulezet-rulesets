rule Trojan_Win32_Fareit_GM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 31 d2 6a ?? 5e 81 c6 [0-04] 87 d6 80 34 01 ?? 41 89 d3 39 d9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}