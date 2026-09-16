rule Trojan_BAT_FormBook_AOF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 16 11 04 a2 25 17 7e 17 00 00 0a a2 25 18 11 01 a2 25 19 17 8c } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}