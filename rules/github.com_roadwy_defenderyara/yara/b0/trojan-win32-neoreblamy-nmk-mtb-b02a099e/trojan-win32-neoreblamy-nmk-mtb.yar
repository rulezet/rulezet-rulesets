rule Trojan_Win32_Neoreblamy_NMK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 4d fc ff eb 04 83 4d fc ff 6a 04 58 6b c0 00 } 		$a_03_1 = {ff 99 f7 bd ?? ?? ff ff 8b c2 99 f7 bd ?? ?? ff ff 8b c2 99 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}