rule Ransom_Win32_Ryuk_MTB_3{
	meta:
		description = "Ransom:Win32/Ryuk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 7d ?? 8b 45 ?? 99 f7 7d ?? 8b 45 ?? 8b 0c 90 90 89 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 45 ?? 60 33 c0 8a 45 ?? 33 c9 8b 4d ?? d2 c8 88 45 ?? 61 8b 4d ?? 03 4d ?? 8a 55 ?? 88 11 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}