rule Trojan_Win32_Redline_GNQ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1e ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 04 1e } 		$a_03_1 = {ff 80 04 1e ?? 83 c4 30 46 3b f7 0f 82 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}