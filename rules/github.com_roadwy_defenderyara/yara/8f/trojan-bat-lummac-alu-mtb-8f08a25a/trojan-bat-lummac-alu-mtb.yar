rule Trojan_BAT_LummaC_ALU_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 16 13 04 2b 27 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 2e 05 09 17 58 2b 01 16 0d 11 04 17 58 13 04 11 04 02 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}