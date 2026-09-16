rule Trojan_BAT_DarkTortilla_RP_MTB_18{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 ec 01 00 06 28 37 00 00 0a 10 00 02 28 37 00 00 0a 28 ed 01 00 06 28 37 00 00 0a 0a 02 74 1c 00 00 01 06 28 69 00 00 0a 28 ee 01 00 06 28 05 01 00 06 28 3d 02 00 06 28 37 00 00 0a 28 19 02 00 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}