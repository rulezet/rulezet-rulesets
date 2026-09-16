rule Trojan_Win64_Tedy_AHE_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e1 45 0f b6 c0 41 8b c1 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 48 63 c8 0f be 14 39 41 03 d3 44 03 c2 41 81 e0 } 		$a_01_1 = {48 63 d8 44 0f b6 54 1c 30 41 02 fa 40 0f b6 cf 0f b6 44 0c 30 88 44 1c 30 44 88 54 0c 30 44 0f b6 44 1c 30 4d 03 c2 41 0f b6 c0 44 0f b6 44 04 30 45 30 04 33 49 ff c3 49 81 fb } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}