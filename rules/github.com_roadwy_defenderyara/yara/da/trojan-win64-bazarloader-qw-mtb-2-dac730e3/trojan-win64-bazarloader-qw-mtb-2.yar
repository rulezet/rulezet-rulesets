rule Trojan_Win64_BazarLoader_QW_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QW!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 ce 44 29 c6 44 0f af ce 41 83 e1 01 41 83 f9 00 0f 94 c3 80 e3 01 88 9d 06 03 00 00 41 83 fb 0a 0f 9c c3 80 e3 01 88 9d 07 03 00 00 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}