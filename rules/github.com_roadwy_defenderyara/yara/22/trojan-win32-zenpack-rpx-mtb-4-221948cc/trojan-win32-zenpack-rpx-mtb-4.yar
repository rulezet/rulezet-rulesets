rule Trojan_Win32_Zenpack_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 eb 1b 89 f8 50 8f 05 ?? ?? ?? ?? 40 42 01 c2 31 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff e0 40 89 d8 50 8f 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}