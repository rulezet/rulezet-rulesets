rule Trojan_AndroidOS_SAgnt_X_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 01 6e 10 ?? ?? 09 00 0c 03 21 34 21 a5 23 56 ?? ?? 01 12 01 10 } 		$a_01_1 = {48 07 0a 02 48 08 03 00 b7 87 8d 77 4f 07 06 02 d8 00 00 01 d8 07 04 ff 37 70 03 00 01 10 d8 02 02 01 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}