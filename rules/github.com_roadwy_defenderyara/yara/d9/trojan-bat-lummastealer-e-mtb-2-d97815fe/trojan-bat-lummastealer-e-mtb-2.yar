rule Trojan_BAT_LummaStealer_E_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 45 4c 57 58 53 59 71 55 6a 66 76 4a 4f 4d 75 71 67 45 4f 43 4a 46 63 42 63 6b 65 46 } 		$a_01_1 = {64 4b 41 6f 4d 7a 56 64 6f 47 4d 52 41 75 55 70 6e 7a 48 4c 59 49 78 2e 64 6c 6c } 		$a_01_2 = {49 45 48 46 65 6c 62 57 70 66 73 6b 52 4b 4f 62 74 4e 45 4f 79 50 73 4b 64 46 50 68 4b } 		$a_01_3 = {62 46 49 53 51 46 58 5a 72 6c 68 6f 77 53 70 70 6a 4d 63 55 4d 45 57 4d 56 4f 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}