rule Trojan_Win64_Emotet_PAJ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 d2 31 c9 41 [0-04] 89 d8 99 f7 ff 48 8b 05 ?? ?? ?? ?? 48 63 d2 8a 14 10 32 14 1e 88 54 1d 00 48 ff c3 48 81 fb ?? ?? ?? ?? 75 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}