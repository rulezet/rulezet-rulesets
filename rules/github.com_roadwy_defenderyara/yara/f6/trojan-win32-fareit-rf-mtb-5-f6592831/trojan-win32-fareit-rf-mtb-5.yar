rule Trojan_Win32_Fareit_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_00_0 = {88 f5 81 34 37 1a 33 e5 b5 90 d9 eb eb 2e 6d 99 } 		$a_81_1 = {49 65 62 47 6b 73 41 78 55 78 34 63 54 34 70 47 64 55 79 6f 4f 64 46 64 32 46 67 58 7a 5a 44 57 77 4d 46 55 46 32 32 39 } 		$a_81_2 = {74 38 6d 75 6f 4e 6d 4c 32 45 46 75 36 59 77 50 45 4d 52 4a 71 67 63 73 63 70 49 6c 76 51 78 4f 45 32 31 38 36 } 	condition:
		((#a_00_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}