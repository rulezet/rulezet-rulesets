rule Ransom_Win32_NetWalker_MTB{
	meta:
		description = "Ransom:Win32/NetWalker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 04 ?? 30 04 0e 46 8b 4c 24 ?? 3b f5 72 90 0a c0 00 8d ?? 01 0f b6 ?? 8a 14 ?? 0f b6 c2 03 c1 0f b6 c8 89 4c 24 1c 0f b6 04 ?? 88 04 ?? 88 14 ?? 0f b6 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}