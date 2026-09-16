rule Trojan_Win32_Redline_GMH_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 6d 6d } 		$a_01_1 = {5a 41 74 67 72 6a 74 79 75 6a 74 79 75 } 		$a_03_2 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-20] 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}