rule Trojan_BAT_Discoste_RS_MTB{
	meta:
		description = "Trojan:BAT/Discoste.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 07 18 6f 0f 00 00 0a 0c 06 08 1f 10 28 10 00 00 0a 6f 11 00 00 0a 26 00 07 18 58 0b 07 02 6f 0c 00 00 0a fe 04 13 04 11 04 2d d3 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}