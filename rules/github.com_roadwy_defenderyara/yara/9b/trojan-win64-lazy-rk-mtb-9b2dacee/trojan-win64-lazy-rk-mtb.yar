rule Trojan_Win64_Lazy_RK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 49 89 43 b8 49 89 4b c0 48 8d 05 ?? ?? ?? ?? 49 89 4b d0 4d 8d 4b b8 49 89 4b d8 48 8b da 49 89 4b e0 44 8d 41 01 49 89 43 c8 89 4c 24 50 49 89 4b f0 48 8b cf } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}