rule Trojan_Win32_Zenpack_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 20 b9 02 00 00 00 e2 11 4a 4a 89 e8 50 8f 05 ?? ?? ?? ?? e9 ?? ?? ?? ?? c3 42 83 c2 07 29 c2 8d 05 ?? ?? ?? ?? 31 38 83 e8 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}