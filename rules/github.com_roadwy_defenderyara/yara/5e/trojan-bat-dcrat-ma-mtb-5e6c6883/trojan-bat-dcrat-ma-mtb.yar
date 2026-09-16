rule Trojan_BAT_DCRat_MA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 00 04 61 28 ?? 0d 00 06 73 ?? 01 00 06 28 ?? 01 00 06 } 		$a_01_1 = {56 00 69 00 73 00 75 00 61 00 6c 00 53 00 74 00 75 00 64 00 69 00 6f 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 2e 00 64 00 6c 00 6c 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}