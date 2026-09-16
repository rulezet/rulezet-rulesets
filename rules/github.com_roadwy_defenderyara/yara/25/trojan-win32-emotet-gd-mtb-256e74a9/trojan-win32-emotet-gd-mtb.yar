rule Trojan_Win32_Emotet_GD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 0f af cb 8d 04 7f 03 d1 2b d0 8b 44 24 ?? 8a 18 8a 0c 32 32 d9 8b 4c 24 ?? 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}