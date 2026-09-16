rule Trojan_Win64_Tedy_NTD_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 84 23 01 00 00 85 c9 75 4a c7 05 9f 9d 01 00 ?? ?? ?? ?? 48 8d 15 e0 f0 00 00 48 8d 0d a1 f0 00 00 e8 44 4a } 		$a_01_1 = {3a 2f 2f 66 74 70 2e 32 71 6b 2e 63 6e 2f 48 44 31 2d 32 2e 64 6c 6c } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}