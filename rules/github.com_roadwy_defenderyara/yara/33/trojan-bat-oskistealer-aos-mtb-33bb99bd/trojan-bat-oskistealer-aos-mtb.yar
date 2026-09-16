rule Trojan_BAT_Oskistealer_AOS_MTB{
	meta:
		description = "Trojan:BAT/Oskistealer.AOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 28 07 00 00 06 58 0c 08 06 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}