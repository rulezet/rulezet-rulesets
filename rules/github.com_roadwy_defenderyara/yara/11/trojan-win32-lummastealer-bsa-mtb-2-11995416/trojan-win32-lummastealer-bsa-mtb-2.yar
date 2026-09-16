rule Trojan_Win32_LummaStealer_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 8b 08 89 4d f4 8b 40 04 89 45 f8 8b 4d f4 8b 45 f8 31 d2 89 0c 24 89 44 24 04 c7 44 24 08 00 00 00 00 e8 c6 ?? ?? ?? 83 f8 00 0f 84 0c 00 00 00 c7 04 24 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}