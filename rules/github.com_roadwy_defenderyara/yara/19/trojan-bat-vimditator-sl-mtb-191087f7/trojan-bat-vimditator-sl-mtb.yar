rule Trojan_BAT_Vimditator_SL_MTB{
	meta:
		description = "Trojan:BAT/Vimditator.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 ad 00 00 70 6f 2a 00 00 0a 10 00 dd 0d 00 00 00 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}