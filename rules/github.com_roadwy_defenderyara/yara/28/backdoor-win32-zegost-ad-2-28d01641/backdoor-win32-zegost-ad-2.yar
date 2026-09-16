rule Backdoor_Win32_Zegost_AD_2{
	meta:
		description = "Backdoor:Win32/Zegost.AD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d6 40 89 44 24 ?? 8a 45 00 3c ?? 74 47 3c 42 74 } 		$a_03_1 = {b9 00 08 00 00 33 c0 8d bc 24 ?? ?? 00 00 50 f3 ab 8b 83 ?? ?? 00 00 8d 94 24 ?? ?? 00 00 68 00 20 00 00 52 50 ff d5 85 c0 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}