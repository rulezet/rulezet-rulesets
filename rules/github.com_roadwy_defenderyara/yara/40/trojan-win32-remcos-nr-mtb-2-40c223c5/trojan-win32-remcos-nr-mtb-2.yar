rule Trojan_Win32_Remcos_NR_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 83 f2 00 0f af 95 ?? ?? ff ff 69 8d ?? ?? ff ff f1 fe c9 98 2b d1 89 95 ?? ?? ff ff e9 ?? ?? ?? ?? c7 85 ?? ?? ff ff 01 00 00 00 } 		$a_03_1 = {2b d0 33 95 ?? ?? ff ff 0f af 95 ?? ?? ff ff 69 8d ?? ?? ff ff f1 fe c9 98 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}