rule Trojan_Win64_ReverseShell_KK_MTB_2{
	meta:
		description = "Trojan:Win64/ReverseShell.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 84 24 bc 00 00 00 89 84 24 84 00 00 00 65 48 8b 04 25 ?? 00 00 00 48 8b 40 18 48 89 c1 48 83 c1 10 48 89 8c 24 88 00 00 00 48 8b 40 10 48 39 c8 48 89 84 24 90 90 00 00 00 } 		$a_01_1 = {5b 45 52 52 4f 52 5d 20 57 53 41 53 74 75 72 74 75 70 20 66 61 69 6c 65 64 2e } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}