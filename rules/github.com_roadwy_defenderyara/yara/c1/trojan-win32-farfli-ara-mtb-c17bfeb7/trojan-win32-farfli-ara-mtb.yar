rule Trojan_Win32_Farfli_ARA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 7d 08 b8 ?? ?? ?? ?? 80 c2 3d 30 14 31 8b ce f7 e6 c1 ea 03 8d 04 92 03 c0 2b c8 f7 d9 1b c9 46 23 d9 3b f7 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}