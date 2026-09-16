rule Trojan_Win32_Encoder_B_2{
	meta:
		description = "Trojan:Win32/Encoder.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 17 00 00 7e 06 c6 45 fb 05 eb 12 90 09 03 00 81 7d } 		$a_01_1 = {85 c0 79 05 05 ff 03 00 00 c1 f8 0a 88 45 fb } 		$a_03_2 = {8a 07 03 c0 88 07 ff 45 ?? 47 83 c3 04 ff 4d } 		$a_03_3 = {7e 04 c6 45 fb 01 90 0a 13 00 81 7d ?? 00 04 00 00 7d 0a 83 7d ?? 06 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}