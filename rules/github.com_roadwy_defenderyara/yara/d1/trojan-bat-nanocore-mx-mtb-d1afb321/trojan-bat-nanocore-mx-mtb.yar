rule Trojan_BAT_Nanocore_MX_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 65 73 68 50 6f 64 73 2e 65 78 65 } 		$a_01_1 = {37 61 34 34 32 37 63 32 2d 34 37 37 33 2d 34 37 37 65 2d 38 66 31 62 2d 36 39 61 63 30 31 66 66 61 38 35 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}