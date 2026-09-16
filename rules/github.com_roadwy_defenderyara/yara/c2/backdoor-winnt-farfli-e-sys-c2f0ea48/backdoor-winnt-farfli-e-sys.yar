rule Backdoor_WinNT_Farfli_E_sys{
	meta:
		description = "Backdoor:WinNT/Farfli.E!sys,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 08 74 11 3b 4c 24 ?? 7d 0b 80 04 01 ?? 41 80 3c 01 00 75 ef [0-01] c2 08 00 } 		$a_01_1 = {3d 24 0c 0b 83 74 29 } 	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*5) >=13
 
}