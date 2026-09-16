rule Trojan_Win32_Emotet_GA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 01 0f af c7 2b d0 8b 44 24 ?? 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f 82 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}