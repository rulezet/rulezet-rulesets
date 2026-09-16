rule Trojan_Win32_Qshell_GKM_MTB{
	meta:
		description = "Trojan:Win32/Qshell.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 8a a5 08 00 03 55 ?? 03 c2 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}