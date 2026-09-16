rule Trojan_Win64_Farfli_KK_MTB{
	meta:
		description = "Trojan:Win64/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 43 10 48 ff c7 80 74 07 ff 22 48 ff c9 } 		$a_01_1 = {48 ff c2 41 ff c1 49 3b d3 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}