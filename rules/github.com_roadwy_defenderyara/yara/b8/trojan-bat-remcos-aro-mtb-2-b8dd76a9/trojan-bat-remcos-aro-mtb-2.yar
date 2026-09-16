rule Trojan_BAT_Remcos_ARO_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 06 00 00 04 02 7e 06 00 00 04 02 91 7e 05 00 00 04 7e 1d 00 00 04 1f 7f 7e 1d 00 00 04 1f 7f 91 02 60 20 a0 00 00 00 5f 9c 59 7e 07 00 00 04 59 d2 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}