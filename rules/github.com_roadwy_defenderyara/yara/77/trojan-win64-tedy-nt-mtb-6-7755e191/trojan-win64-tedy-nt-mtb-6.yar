rule Trojan_Win64_Tedy_NT_MTB_6{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 ff c0 48 ff c2 48 83 c0 28 49 3b d1 7c e1 eb 19 49 63 c0 48 8d 0c 80 41 8b 44 ca ?? 41 8b 74 ca ?? 4a 8d 1c 38 4e 8d 24 28 41 8b 04 24 4c 8b ac 24 48 03 00 00 } 		$a_01_1 = {65 78 70 6c 6f 69 74 61 74 69 6f 6e 20 64 } 		$a_01_2 = {45 58 50 4c 4f 49 54 5c 42 49 4e 41 52 59 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}