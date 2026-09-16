rule Trojan_BAT_Launcher_A_MTB_2{
	meta:
		description = "Trojan:BAT/Launcher.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 78 00 6e 00 6f 00 64 00 33 00 32 00 5c 00 78 00 6e 00 6f 00 64 00 33 00 32 00 75 00 70 00 2e 00 65 00 78 00 65 00 } 		$a_01_1 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}