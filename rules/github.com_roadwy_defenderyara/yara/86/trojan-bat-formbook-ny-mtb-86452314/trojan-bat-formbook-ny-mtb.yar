rule Trojan_BAT_FormBook_NY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 41 00 00 0a 26 11 0a 11 0d 16 11 0b 11 0c 16 6f ?? ?? ?? 0a 25 26 13 0f 7e ?? ?? ?? 04 11 0c 16 11 0f 6f ?? ?? ?? 0a } 		$a_01_1 = {46 47 53 54 48 44 47 46 48 4a 47 4a 48 44 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}