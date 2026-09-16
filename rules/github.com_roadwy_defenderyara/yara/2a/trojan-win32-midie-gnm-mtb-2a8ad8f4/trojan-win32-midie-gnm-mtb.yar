rule Trojan_Win32_Midie_GNM_MTB{
	meta:
		description = "Trojan:Win32/Midie.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d8 bb 99 00 00 00 ?? 31 c3 80 07 ?? 80 2f ?? ?? 89 d8 bb ?? ?? ?? ?? ?? 31 c3 f6 2f 47 e2 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}