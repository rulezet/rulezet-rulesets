rule Trojan_Win64_Emotet_EB_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 2b c1 4c 63 c2 4d 6b c0 15 4c 03 c0 48 8b 44 24 28 41 8a 0c 08 41 32 0c 02 43 88 0c 1a 49 83 c2 01 44 3b 64 24 20 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}