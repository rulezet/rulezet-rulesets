rule Trojan_BAT_RedLine_MF_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 9a 1f 10 28 ?? ?? ?? 0a 9c 11 04 17 d6 13 04 00 11 04 20 ?? ?? ?? 00 fe 04 13 06 11 06 2d db 09 13 05 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}