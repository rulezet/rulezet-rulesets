rule Trojan_BAT_FormBook_AOF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7b 2a 00 00 04 72 92 07 00 70 6f ?? ?? ?? 0a 00 02 7b 2a 00 00 04 16 6f ?? ?? ?? 0a 00 73 7f 00 00 0a 0b 06 72 bc 07 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 0c 08 } 		$a_01_1 = {50 00 72 00 6f 00 76 00 61 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}