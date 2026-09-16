rule Trojan_Win64_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f 57 ff 4c 8b 35 48 31 9a 00 65 4d 8b 36 4d 8b 36 48 8b 04 24 48 8b 5c 24 50 48 01 d8 } 		$a_01_1 = {49 8b 4e 30 c6 81 e5 00 00 00 01 48 8b 0d 3d 69 90 00 48 83 39 00 0f 85 16 02 00 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}