rule Trojan_BAT_Remcos_MF_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.MF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 5f 13 08 07 09 11 08 d2 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}