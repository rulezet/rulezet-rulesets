rule Trojan_Win32_Copack_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Copack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 31 39 01 d3 4a 41 42 89 da 89 d2 39 c1 75 d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}