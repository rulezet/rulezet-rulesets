rule Trojan_Win64_BazarLoader_QV_MTB_3{
	meta:
		description = "Trojan:Win64/BazarLoader.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 0d 8b ca 41 ff c0 c1 e9 10 88 08 48 ff c0 49 63 c8 48 3b ce 73 0d 8b ca 41 ff c0 c1 e9 08 88 08 48 ff c0 49 63 c8 48 3b ce 73 08 41 ff c0 88 10 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}