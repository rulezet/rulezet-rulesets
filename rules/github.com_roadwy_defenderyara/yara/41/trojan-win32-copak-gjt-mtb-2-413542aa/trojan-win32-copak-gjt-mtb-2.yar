rule Trojan_Win32_Copak_GJT_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 59 81 c1 ?? ?? ?? ?? 31 1f 47 81 c1 ?? ?? ?? ?? 39 d7 75 ?? c3 81 c6 ?? ?? ?? ?? 8d 1c 03 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}