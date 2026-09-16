rule Trojan_Win32_Kazuar_C_dha{
	meta:
		description = "Trojan:Win32/Kazuar.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 1c 0f af 45 14 89 c2 8b 45 18 01 d0 89 45 1c 8b 55 08 8b 45 ?? 01 d0 0f b6 00 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}