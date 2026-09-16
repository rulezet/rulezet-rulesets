rule Trojan_Win32_Fragtor_NF_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 c8 4f 46 00 6b c9 ?? 03 c8 eb 11 8b 55 ?? 2b 50 0c 81 fa 00 00 10 00 72 09 83 c0 ?? 3b c1 72 eb 33 c0 } 		$a_01_1 = {47 5a 47 4c 58 54 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}