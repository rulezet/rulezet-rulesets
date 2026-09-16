rule Trojan_BAT_LummaC_ALU_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 00 77 96 6a ?? ?? ?? ?? ?? 95 bb d7 2a a1 f5 1d 92 e0 e4 13 f1 e4 05 07 84 1c 05 ed 19 } 		$a_01_1 = {59 00 76 00 6f 00 6e 00 6e 00 65 00 47 00 72 00 61 00 63 00 65 00 45 00 6c 00 65 00 61 00 6e 00 6f 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}