rule Trojan_Win32_RanumBot_KMG_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 44 24 10 a1 ?? ?? ?? ?? 3d 1a 0c 00 00 75 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}