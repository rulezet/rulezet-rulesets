rule Trojan_Win32_Kazuar_C_dha_2{
	meta:
		description = "Trojan:Win32/Kazuar.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 83 ec ?? c6 45 ?? 31 c6 45 ?? c0 c6 45 ?? c2 c6 45 ?? 14 c6 45 ?? 00 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}