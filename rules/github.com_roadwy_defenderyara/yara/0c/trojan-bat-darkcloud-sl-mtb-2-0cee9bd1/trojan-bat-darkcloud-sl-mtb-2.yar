rule Trojan_BAT_DarkCloud_SL_MTB_2{
	meta:
		description = "Trojan:BAT/DarkCloud.SL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 0d 72 1d 00 00 70 2b 09 18 2d 0d 26 de 1d 07 2b f0 6f 45 00 00 0a 2b f0 0a 2b f1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}