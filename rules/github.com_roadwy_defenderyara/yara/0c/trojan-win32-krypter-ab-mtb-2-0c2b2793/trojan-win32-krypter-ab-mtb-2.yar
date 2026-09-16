rule Trojan_Win32_Krypter_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Krypter.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5f 89 30 5e 5b c9 c2 90 0a 2f 00 2b 75 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b 45 ?? 89 78 } 		$a_01_1 = {4c 6f 63 61 6c 41 6c 6c 6f 63 } 		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}