rule Trojan_Win64_Tedy_ATY_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d6 48 89 55 97 41 b8 ?? ?? ?? ?? 4c 89 45 9f 88 55 87 c7 45 a7 ?? ?? ?? ?? b1 14 80 f1 55 48 8d 5b 01 49 3b d0 73 1f 48 8d 42 01 48 89 45 97 48 8d 45 87 49 83 f8 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}