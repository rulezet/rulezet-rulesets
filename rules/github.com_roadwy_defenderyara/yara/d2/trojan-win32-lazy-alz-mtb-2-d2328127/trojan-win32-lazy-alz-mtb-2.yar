rule Trojan_Win32_Lazy_ALZ_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 68 00 02 00 00 8d 85 e4 fd ff ff 50 e8 ?? ?? ?? ?? 83 c4 28 8d 86 08 04 00 00 8d 4e 08 6a 00 50 68 ff 03 00 00 51 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 37 e8 } 		$a_01_1 = {6a 00 8d 86 08 04 00 00 50 68 ff 03 00 00 8d 46 08 50 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 37 e8 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}