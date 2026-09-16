rule Trojan_Win32_Glupteba_AV_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 2e 15 8b 15 ?? ?? ?? ?? 88 0c 32 3d 03 02 00 00 75 27 } 		$a_00_1 = {75 03 83 c1 15 40 3d 45 74 8d 00 7c ee } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}