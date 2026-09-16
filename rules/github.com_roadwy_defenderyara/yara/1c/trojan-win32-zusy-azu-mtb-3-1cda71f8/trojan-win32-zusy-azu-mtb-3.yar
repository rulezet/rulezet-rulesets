rule Trojan_Win32_Zusy_AZU_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 02 f3 a5 8b ca 83 e1 03 68 98 64 41 00 f3 a4 50 e8 ?? ?? ?? ?? 8b f0 8d 85 8c fe ff ff 56 6a 64 6a 01 50 } 		$a_03_1 = {8a 47 01 8d 7f 01 84 c0 75 f6 a1 ?? ?? ?? ?? 89 07 8d 45 8c 6a 00 50 ff 15 ?? ?? ?? ?? 8b 4d fc 5f 33 cd 5e } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}