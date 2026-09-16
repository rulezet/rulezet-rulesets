rule Trojan_Win32_ClipBanker_GZZ_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 6a 0d ff 15 ?? ?? ?? ?? 89 45 e4 8b 45 e4 50 ff 15 ?? ?? ?? ?? 89 45 e0 8b 4d e0 51 } 		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}