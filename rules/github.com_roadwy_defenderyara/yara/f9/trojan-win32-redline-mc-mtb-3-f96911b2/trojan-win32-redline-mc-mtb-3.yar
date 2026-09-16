rule Trojan_Win32_Redline_MC_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 75 41 46 47 73 79 47 73 68 41 73 74 75 36 37 38 65 32 38 72 } 		$a_03_1 = {0f b6 4d d7 8b 45 d8 33 d2 be 04 00 00 00 f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d df 8b 45 d8 8a 88 ?? ?? ?? ?? 88 4d d6 0f b6 55 df 8b 45 d8 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 d8 88 8a ?? ?? ?? ?? 68 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}