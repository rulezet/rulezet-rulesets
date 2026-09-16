rule Trojan_BAT_Fsysna_AFS_MTB_3{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 4d 12 01 28 ?? 00 00 0a 0c 08 73 21 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 09 28 } 		$a_01_1 = {74 00 77 00 6f 00 62 00 69 00 74 00 36 00 39 00 20 00 6f 00 72 00 20 00 6c 00 69 00 66 00 65 00 6f 00 66 00 61 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}