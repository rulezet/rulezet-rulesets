rule Trojan_BAT_FormBook_EWE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 06 11 05 06 ?? ?? ?? ?? ?? 5d ?? ?? ?? ?? ?? 09 11 05 91 61 d2 9c 00 11 05 17 58 13 05 } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}