rule Trojan_BAT_NjRat_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/NjRat.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 25 00 00 0a 0c 08 07 ?? ?? 00 00 0a 17 73 27 00 00 0a 0d 09 02 16 02 8e b7 ?? ?? 00 00 0a 09 ?? ?? 00 00 0a de 0a 09 2c 06 09 ?? ?? 00 00 0a dc 08 ?? ?? 00 00 0a 0a de 18 de 0a } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}