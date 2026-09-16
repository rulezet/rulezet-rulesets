rule Trojan_BAT_Vimditator_SL_MTB_2{
	meta:
		description = "Trojan:BAT/Vimditator.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 2d 0b 2b 0b 72 61 00 00 70 2b 07 2b 0c de 1a 07 2b f2 6f 1f 00 00 0a 2b f2 0a 2b f1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}