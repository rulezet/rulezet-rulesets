rule Trojan_Win32_Copack_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Copack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 31 89 df 81 c1 04 00 00 00 81 c2 ?? ?? ?? ?? 39 c1 75 e7 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}