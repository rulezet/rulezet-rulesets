rule Ransom_Win32_FileCoder_PC_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 89 f9 81 c1 35 1b 00 00 66 89 cb 8b 4c 24 ?? 66 89 5c 24 ?? 8a 84 01 ?? ?? ?? ?? 88 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 0f b6 0c 0a 66 89 7c 24 ?? 0f b6 54 24 ?? 29 d1 88 c8 88 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 09 c9 09 d2 8b 74 24 ?? 89 54 24 ?? 89 4c 24 ?? 8b 4c 24 ?? 88 04 31 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}