rule Trojan_Win64_BazarLoader_QV_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 87 dd 4c 89 6c 24 08 49 87 dd 49 87 ed 4c 89 6c 24 10 4c 87 ed 48 89 74 24 18 48 87 f9 48 89 4c 24 20 48 87 f9 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}