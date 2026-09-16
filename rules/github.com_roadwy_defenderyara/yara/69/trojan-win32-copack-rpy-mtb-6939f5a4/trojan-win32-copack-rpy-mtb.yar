rule Trojan_Win32_Copack_RPY_MTB{
	meta:
		description = "Trojan:Win32/Copack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 31 08 42 09 d3 40 4a 39 f8 75 e3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}