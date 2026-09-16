rule Trojan_Win64_Rozena_SPF_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 4c 24 50 41 b8 ff 03 00 00 48 8d 55 f0 48 8b cf ff 15 ?? ?? ?? ?? 44 8b 4c 24 50 4c 8d 45 f0 48 8b 54 24 60 48 8d 4c 24 58 e8 ?? ?? ?? ?? 83 7c 24 50 00 75 } 		$a_03_1 = {48 8b 7c 24 60 48 8b 74 24 58 48 2b fe 41 b9 ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 48 8b d7 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 4c 8b c7 48 8b d6 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}