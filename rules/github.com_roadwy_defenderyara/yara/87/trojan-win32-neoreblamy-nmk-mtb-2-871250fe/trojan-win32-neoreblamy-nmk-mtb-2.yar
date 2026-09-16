rule Trojan_Win32_Neoreblamy_NMK_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 05 48 83 c8 fe 40 85 c0 74 09 } 		$a_03_1 = {6a 05 59 f7 f9 03 85 ?? ?? ff ff 99 8b f0 8b fa } 		$a_03_2 = {8b f0 6a 05 58 2b 85 ?? ?? ff ff 99 6a 05 59 f7 f9 52 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=4
 
}