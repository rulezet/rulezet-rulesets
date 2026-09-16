rule Trojan_Win32_Fareit_V_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 14 10 f7 ef 03 d7 80 f1 ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 88 0c 32 8a 04 2e 3c ?? 77 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}