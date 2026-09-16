rule Trojan_Win32_Emotet_BB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d1 8b 4c 24 ?? 03 d0 8d 04 09 2b d0 8b 44 24 ?? 03 d5 8a 18 8a 0c 3a 32 d9 8b 4c 24 ?? 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}