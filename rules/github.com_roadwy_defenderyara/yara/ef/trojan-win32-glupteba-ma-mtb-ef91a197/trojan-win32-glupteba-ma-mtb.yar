rule Trojan_Win32_Glupteba_MA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {7e 49 55 8b 2d ?? ?? ?? ?? 8b ff 81 ff 85 02 00 00 75 14 } 		$a_00_1 = {30 04 1e 81 ff 91 05 00 00 75 0e } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}