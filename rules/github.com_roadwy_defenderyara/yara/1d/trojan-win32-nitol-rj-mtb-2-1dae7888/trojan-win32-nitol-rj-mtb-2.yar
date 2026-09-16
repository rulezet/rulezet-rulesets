rule Trojan_Win32_Nitol_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Nitol.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 52 45 56 45 44 21 20 49 20 53 4d 4f 4b 45 20 47 41 4e 4a 41 20 45 56 45 52 59 20 44 41 59 21 } 		$a_01_1 = {73 64 63 6d 62 78 74 72 67 6b 68 32 } 		$a_01_2 = {70 76 74 66 6e 74 6e 72 78 76 6d 73 63 70 68 6b 67 62 66 74 64 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}