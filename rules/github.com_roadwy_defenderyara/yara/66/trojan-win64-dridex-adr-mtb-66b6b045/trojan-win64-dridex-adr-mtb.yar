rule Trojan_Win64_Dridex_ADR_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 48 8b 4c 24 40 48 81 c1 ?? ?? ?? ?? 89 44 24 4c 8a 54 24 03 80 f2 ff 4c 8b 44 24 28 88 54 24 37 8a 54 24 03 80 f2 d7 4c 8b 4c 24 20 47 8a 14 01 88 54 24 37 4c 8b 5c 24 10 47 88 14 03 66 8b 34 24 66 81 ce 07 0d 49 01 c8 } 		$a_01_1 = {45 6f 66 6b 69 77 65 72 65 7a 34 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}