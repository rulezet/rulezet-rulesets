rule Trojan_Win64_Barys_GME_MTB{
	meta:
		description = "Trojan:Win64/Barys.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {b1 9f 33 7e 9c 87 18 89 80 ?? ?? ?? ?? 0a 82 } 		$a_01_1 = {37 65 37 66 65 6b 61 51 } 		$a_01_2 = {72 46 35 75 58 52 78 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}