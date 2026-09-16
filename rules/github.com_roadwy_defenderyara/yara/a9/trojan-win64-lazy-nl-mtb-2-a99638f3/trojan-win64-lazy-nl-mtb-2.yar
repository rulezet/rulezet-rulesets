rule Trojan_Win64_Lazy_NL_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 c3 10 48 85 db 74 35 8b 4d 60 44 8b cf 44 89 74 24 28 4c 8b c6 ba 01 00 00 00 48 89 5c 24 20 ff 15 20 c1 01 00 33 ff 85 c0 75 39 48 8d 4b f0 81 39 dd } 		$a_01_1 = {33 c0 48 8b 4d 00 48 33 cd e8 bb 05 00 00 48 8b 5d 30 48 8b 75 38 48 8b 7d 40 4c 8b 6d 48 48 8d 65 10 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}