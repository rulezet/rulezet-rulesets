rule Trojan_Win32_Zenpak_GNE_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 89 1d ?? ?? ?? ?? 4a 83 c2 ?? 83 ea ?? 40 8d 05 ?? ?? ?? ?? 31 38 8d 05 ?? ?? ?? ?? 50 c3 48 40 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}