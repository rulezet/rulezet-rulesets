rule Trojan_Win32_Fragtor_KAE_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 42 61 72 74 65 6e 64 65 72 20 53 69 6d 75 6c 61 74 6f 72 21 } 		$a_01_1 = {67 63 72 79 5f 73 65 78 70 5f 62 75 69 6c 64 5f 61 72 72 61 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}