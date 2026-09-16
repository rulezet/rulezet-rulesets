rule Trojan_Win64_LummaStealer_BSA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 69 48 8b 48 40 84 01 48 8b 50 48 48 8d 35 b3 04 00 00 48 89 b4 24 } 		$a_01_1 = {49 3b 66 10 76 25 55 48 89 e5 48 83 ec 08 4d 8b 66 20 4d 85 e4 75 1b } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}