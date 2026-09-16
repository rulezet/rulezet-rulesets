rule Trojan_Win32_Convagent_ARR_MTB_3{
	meta:
		description = "Trojan:Win32/Convagent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 8a 9c 0d ?? ?? ?? ?? 99 f7 ff 8b 45 08 0f b6 04 02 } 		$a_01_1 = {47 65 6e 65 72 69 63 4c 6f 67 49 6d 70 6c } 		$a_01_2 = {5b 4f 72 61 6e 67 65 36 34 5d 20 44 65 6c 65 74 65 46 69 6c 65 50 61 74 68 3a 25 77 5a } 	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}