rule Trojan_Win32_Convagent_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 48 8d 55 01 8b 44 24 74 8b 4c 24 40 0f b6 5c 24 25 } 		$a_01_1 = {5f 5a 31 36 47 65 74 49 6e 66 65 63 74 69 6f 6e 49 6e 66 6f 50 31 35 5f 49 4e 46 45 43 54 49 4f 4e 5f 49 4e 46 4f } 		$a_01_2 = {5f 5a 32 34 44 65 63 72 79 70 74 41 6e 64 45 78 74 72 61 63 74 50 61 79 6c 6f 61 64 50 76 6d 50 53 5f 50 6d } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}