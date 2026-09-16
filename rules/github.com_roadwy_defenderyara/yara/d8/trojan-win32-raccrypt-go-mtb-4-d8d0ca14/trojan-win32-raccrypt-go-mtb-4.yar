rule Trojan_Win32_Raccrypt_GO_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 ?? 75 } 		$a_02_1 = {25 bb 52 c0 5d 8b [0-02] 8b [0-04] c1 ?? 05 03 [0-04] c1 [0-01] 04 03 [0-06] 33 ?? 33 } 		$a_02_2 = {25 bb 52 c0 5d 8b [0-02] 8b [0-04] c1 ?? 04 03 [0-06] 33 [0-08] c1 [0-01] 05 03 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}