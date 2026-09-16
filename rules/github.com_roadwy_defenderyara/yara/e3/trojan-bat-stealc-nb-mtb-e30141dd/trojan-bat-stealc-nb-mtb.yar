rule Trojan_BAT_StealC_NB_MTB{
	meta:
		description = "Trojan:BAT/StealC.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 93 61 11 0b ?? 2c 00 00 1b 11 09 11 0c 58 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}