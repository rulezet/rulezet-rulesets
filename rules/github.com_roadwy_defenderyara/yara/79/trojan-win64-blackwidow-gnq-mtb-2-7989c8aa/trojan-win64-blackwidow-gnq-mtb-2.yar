rule Trojan_Win64_BlackWidow_GNQ_MTB_2{
	meta:
		description = "Trojan:Win64/BlackWidow.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8a 14 10 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 44 30 14 0f c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}