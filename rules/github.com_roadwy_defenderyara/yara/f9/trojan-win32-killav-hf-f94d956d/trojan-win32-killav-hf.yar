rule Trojan_Win32_Killav_HF{
	meta:
		description = "Trojan:Win32/Killav.HF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 0f be 08 85 c9 74 6d 8b 55 f8 0f be 02 83 e8 01 8b 4d f8 88 01 b0 6f b0 ff b0 f5 b0 f5 } 		$a_01_1 = {8b 55 f8 83 c2 01 89 55 f8 b0 6f b0 ff b0 f5 b0 f5 b0 38 b0 70 b0 6f b0 49 b0 c0 b0 89 b0 47 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}