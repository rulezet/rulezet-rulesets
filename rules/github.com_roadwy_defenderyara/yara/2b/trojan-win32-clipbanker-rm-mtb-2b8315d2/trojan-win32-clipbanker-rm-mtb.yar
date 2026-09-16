rule Trojan_Win32_ClipBanker_RM_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c1 c4 7e 00 00 8b 55 ?? 8b 02 2b c1 8b 4d ?? 89 01 8b 15 ?? ?? ?? ?? a1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}