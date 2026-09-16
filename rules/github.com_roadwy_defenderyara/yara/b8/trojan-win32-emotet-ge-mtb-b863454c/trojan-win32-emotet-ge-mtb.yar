rule Trojan_Win32_Emotet_GE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 14 2f 03 c2 33 d2 f7 35 [0-04] 58 2b c1 0f af c3 03 d0 8b 44 24 ?? 2b d6 8a 0c 3a 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}