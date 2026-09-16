rule Trojan_Win32_Copak_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 c2 29 d2 31 31 b8 ?? ?? ?? ?? 29 c2 81 c1 ?? ?? ?? ?? 39 f9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}