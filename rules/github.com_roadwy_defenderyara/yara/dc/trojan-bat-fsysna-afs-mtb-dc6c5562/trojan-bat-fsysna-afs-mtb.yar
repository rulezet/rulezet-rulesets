rule Trojan_BAT_Fsysna_AFS_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 13 00 00 0a 0a 73 14 00 00 0a 0b 07 72 1f 00 00 70 6f ?? 00 00 0a 0a de 0a 07 2c 06 07 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}