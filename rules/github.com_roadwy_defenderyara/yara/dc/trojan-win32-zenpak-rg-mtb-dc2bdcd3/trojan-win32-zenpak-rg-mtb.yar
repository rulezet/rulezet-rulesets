rule Trojan_Win32_Zenpak_RG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 83 c0 09 29 c2 8d 05 ?? ?? ?? ?? 89 28 83 f2 05 83 e8 07 83 f2 09 31 3d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}