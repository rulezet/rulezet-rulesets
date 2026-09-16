rule Trojan_BAT_NjRat_NN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 02 11 ?? 91 06 11 05 08 5d 91 61 9c } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}