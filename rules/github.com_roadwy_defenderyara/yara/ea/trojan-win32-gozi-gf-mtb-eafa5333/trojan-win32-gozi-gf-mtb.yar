rule Trojan_Win32_Gozi_GF_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f3 2b fe 25 [0-10] 81 6d [0-20] bb ?? ?? ?? ?? 81 45 [0-20] 8b 4d ?? 8b 55 ?? 8b c7 d3 e0 8b cf c1 e9 ?? 03 4d ?? 03 45 ?? 03 d7 33 c1 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}