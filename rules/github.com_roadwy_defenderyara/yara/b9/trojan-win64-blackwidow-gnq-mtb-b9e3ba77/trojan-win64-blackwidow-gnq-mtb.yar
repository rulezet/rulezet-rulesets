rule Trojan_Win64_BlackWidow_GNQ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c5 c5 fd cb c5 c5 73 dc ?? c5 e5 69 d7 44 30 14 0f c5 dd 60 e1 48 ff c1 c5 c5 68 f9 48 89 c8 c4 e3 fd 00 ff ?? 48 81 f9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}