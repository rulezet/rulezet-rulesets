rule Trojan_Win32_Glupteba_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 14 0e 3d 03 02 00 00 75 ?? 89 3d ?? ?? ?? ?? 41 3b c8 72 } 		$a_02_1 = {30 04 37 83 fb 19 75 ?? 33 c0 50 8d 4c 24 ?? 51 50 50 50 50 ff 15 ?? ?? ?? ?? 46 3b f3 7c } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}