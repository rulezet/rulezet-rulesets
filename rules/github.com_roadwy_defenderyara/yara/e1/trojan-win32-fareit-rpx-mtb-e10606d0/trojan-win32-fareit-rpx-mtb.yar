rule Trojan_Win32_Fareit_RPX_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5e fc 31 c9 81 c9 fc 1f 00 00 89 c7 51 f3 a4 59 81 34 08 ?? ?? ?? ?? 83 e9 04 7d f4 ff e0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}