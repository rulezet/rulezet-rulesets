rule Trojan_Win32_EyeStye_N{
	meta:
		description = "Trojan:Win32/EyeStye.N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 45 f8 d9 09 00 00 8b 55 f0 81 f2 00 00 00 99 89 15 ?? ?? 42 00 8b 05 ?? ?? 43 00 f7 d0 05 ?? ?? 00 00 c1 e8 ?? 89 45 ec } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}