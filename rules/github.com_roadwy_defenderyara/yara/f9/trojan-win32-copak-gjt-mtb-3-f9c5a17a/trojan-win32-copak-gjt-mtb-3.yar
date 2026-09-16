rule Trojan_Win32_Copak_GJT_MTB_3{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 34 24 83 c4 ?? e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 83 ec ?? 89 14 24 5a 31 37 21 da 47 81 ea ?? ?? ?? ?? 29 db 39 cf } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}