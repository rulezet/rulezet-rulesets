rule Trojan_Win32_Zenpack_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 81 00 e1 34 ef c6 c3 01 08 c3 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}