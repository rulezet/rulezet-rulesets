rule Trojan_BAT_FormBook_AFK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 03 91 1d 59 1f 09 59 d2 25 0a 9c 06 2a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}