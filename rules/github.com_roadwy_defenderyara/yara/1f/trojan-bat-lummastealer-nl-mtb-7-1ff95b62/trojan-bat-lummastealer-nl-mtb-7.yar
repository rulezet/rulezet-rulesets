rule Trojan_BAT_LummaStealer_NL_MTB_7{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 61 74 65 79 6b 6f 5f 63 72 79 70 74 65 64 } 		$a_01_1 = {24 32 61 32 38 31 32 37 39 2d 65 31 61 35 2d 34 62 30 61 2d 62 32 65 66 2d 31 39 32 64 65 39 35 64 33 38 63 64 } 		$a_01_2 = {4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 20 62 72 6f 77 73 65 72 20 66 6f 72 20 61 6c 6c } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}