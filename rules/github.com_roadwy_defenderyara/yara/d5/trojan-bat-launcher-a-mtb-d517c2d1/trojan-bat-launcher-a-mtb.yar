rule Trojan_BAT_Launcher_A_MTB{
	meta:
		description = "Trojan:BAT/Launcher.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 1d 00 00 0a 26 de 0c 28 1e 00 00 0a 28 1f 00 00 0a de 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}