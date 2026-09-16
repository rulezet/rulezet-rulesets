rule Trojan_Win32_StealC_GNM_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 ?? 03 74 24 ?? 8d 0c 1f 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}