rule Trojan_Win32_Stelega_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Stelega.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 46 6b 44 69 40 73 40 67 40 68 48 6e 3c 71 40 6b 3c 74 3c 66 39 71 41 6b 48 65 3d 66 3a 72 } 		$a_81_1 = {6c 3c 74 3c 69 3d 71 42 68 3c 73 40 67 40 6a 42 72 41 6d 3c 73 39 70 3d 74 3c 68 43 6b 45 67 3e 68 47 6d } 		$a_81_2 = {6c 45 68 39 6a 45 65 40 72 40 71 44 65 46 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}