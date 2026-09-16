rule Trojan_BAT_DeliveryCheck_B_dha{
	meta:
		description = "Trojan:BAT/DeliveryCheck.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 06 1a 58 4a 03 06 1a 58 4a 03 8e 69 5d 91 9e } 	condition:
		((#a_01_0  & 1)*100) >=100
 
}