rule Trojan_Win32_Emotet_RW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 ?? 0f af c7 2b d0 8b 44 24 ?? 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}