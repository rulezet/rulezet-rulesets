rule Trojan_BAT_AsyncRAT_ARA_MTB_8{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 74 2e 6d 65 2f 47 68 6f 73 74 48 61 63 6b 65 72 73 4e 65 74 77 6f 72 6b 3e } 		$a_00_1 = {54 00 57 00 39 00 36 00 61 00 57 00 78 00 73 00 59 00 53 00 38 00 31 00 4c 00 6a 00 41 00 67 00 4b 00 } 		$a_00_2 = {55 00 32 00 39 00 6d 00 64 00 48 00 64 00 68 00 63 00 6d 00 56 00 63 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}