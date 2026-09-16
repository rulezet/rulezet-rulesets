rule Trojan_Win32_Zenpack_EM_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 31 c9 89 c2 88 d3 8b 55 e8 88 1c 02 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}