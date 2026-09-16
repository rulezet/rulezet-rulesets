rule Trojan_Win32_Azorult_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.AD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 89 4c 24 14 8d 64 24 00 81 f9 0d 04 00 00 75 0a } 		$a_01_1 = {33 c9 33 c0 8d 54 24 18 52 66 89 44 24 14 66 89 4c 24 16 8b 44 24 14 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}