rule Trojan_BAT_Taskun_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 61 06 07 17 58 09 5d 91 59 20 00 01 00 00 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}