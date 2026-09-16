rule Trojan_Win32_Amadey_AMY_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 f4 69 42 00 a3 ?? ?? ?? ?? ff d6 85 c0 74 0a 68 10 6a 42 00 50 ff d7 } 		$a_03_1 = {33 c0 68 f4 69 42 00 a3 ?? ?? ?? ?? ff d6 85 c0 74 0a 68 20 6a 42 00 50 ff d7 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}