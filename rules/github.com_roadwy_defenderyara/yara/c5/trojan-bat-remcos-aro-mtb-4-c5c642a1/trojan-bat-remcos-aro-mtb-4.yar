rule Trojan_BAT_Remcos_ARO_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 1e 00 00 0a 0b 73 1f 00 00 0a 0c 07 16 73 20 00 00 0a 73 21 00 00 0a 0d 09 08 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 04 de 2b } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}