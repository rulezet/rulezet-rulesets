rule Trojan_BAT_Fsysna_AFS_MTB_2{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 2b 1e 00 08 11 06 16 11 07 6f 22 00 00 0a 00 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 00 11 07 16 fe 02 13 09 11 09 2d d7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}