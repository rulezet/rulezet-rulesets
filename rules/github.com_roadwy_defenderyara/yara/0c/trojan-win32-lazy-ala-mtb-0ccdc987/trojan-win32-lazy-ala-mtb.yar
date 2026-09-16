rule Trojan_Win32_Lazy_ALA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 68 b2 6c 41 00 68 f0 3e 41 00 6a 00 ff 15 2c f1 40 00 ff 75 14 ff 35 38 7b 41 00 ff 15 1c f1 40 00 ff 35 38 7b 41 00 ff 15 64 f1 40 00 6a 6d 53 ff 15 } 		$a_01_1 = {8b 0d 00 60 41 00 56 8b 35 bc 73 41 00 83 e1 1f 33 35 00 60 41 00 d3 ce 85 f6 } 		$a_01_2 = {8b 0d 00 60 41 00 8b 15 bc 73 41 00 83 e1 1f 33 15 00 60 41 00 d3 ca 85 d2 0f 95 c0 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}