rule Trojan_Win32_Fareit_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 a1 ?? ?? ?? ?? 8b 40 ?? 99 03 04 24 13 54 24 ?? 83 c4 08 } 		$a_03_1 = {8b 06 8b 00 25 ff ff 00 00 50 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 16 89 02 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}