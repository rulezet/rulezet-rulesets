rule Trojan_Win32_Emotet_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c6 99 f7 f9 0f b6 04 3e 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 0f be 8a ?? ?? ?? ?? 03 cb 03 c1 99 b9 0f 27 00 00 f7 f9 } 		$a_00_1 = {0f b6 04 3e 8a 14 3b 88 14 3e 83 c6 01 81 fe 0f 27 00 00 88 04 3b 0f 8c } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}