rule Trojan_Win32_Injuke_RB_MTB_5{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 02 8b 04 08 89 45 e4 69 45 e4 ?? ?? ?? ?? 89 45 e4 8b 45 e4 c1 e8 18 33 45 e4 89 45 e4 69 45 e4 ?? ?? ?? ?? 89 45 e4 69 45 f4 ?? ?? ?? ?? 89 45 f4 8b 45 e4 33 45 f4 89 45 f4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}