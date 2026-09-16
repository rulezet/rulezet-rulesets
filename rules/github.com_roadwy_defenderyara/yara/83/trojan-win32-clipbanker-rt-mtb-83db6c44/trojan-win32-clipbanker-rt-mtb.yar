rule Trojan_Win32_ClipBanker_RT_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b f8 59 8b f2 8a 0c 75 ?? ?? ?? ?? 88 0c 3e 46 3b f3 72 ?? 8b c2 83 e0 0f 8a 80 ?? ?? ?? ?? 30 04 3a 42 3b d3 72 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}