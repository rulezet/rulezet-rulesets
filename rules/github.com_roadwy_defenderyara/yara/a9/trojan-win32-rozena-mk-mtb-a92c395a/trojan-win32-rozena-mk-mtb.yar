rule Trojan_Win32_Rozena_MK_MTB{
	meta:
		description = "Trojan:Win32/Rozena.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 0f 48 c2 c1 f8 03 0f b6 84 05 ?? ?? ff ff 0f be d0 8b 45 ?? 83 e0 07 89 c1 d3 fa 89 d0 83 e0 01 85 c0 } 		$a_03_1 = {0f b6 00 0f be c0 34 ff 89 c2 8b 45 ?? 89 44 24 04 89 14 24 } 	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}