rule Trojan_Win32_Raccrypt_GP_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 0f 82 } 		$a_02_1 = {25 bb 52 c0 5d 8b [0-02] 8b [0-04] c1 ?? 04 03 [0-04] c1 [0-01] 05 03 [0-06] 33 ?? 33 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}