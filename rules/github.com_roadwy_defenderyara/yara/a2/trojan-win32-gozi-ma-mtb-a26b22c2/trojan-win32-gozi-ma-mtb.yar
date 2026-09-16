rule Trojan_Win32_Gozi_MA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 10 88 14 08 8b d3 ff 05 ?? ?? ?? ?? 8b 4e 64 8b 86 88 00 00 00 c1 ea 08 88 14 01 ff 46 64 8b 0d ?? ?? ?? ?? 8b 81 08 01 00 00 35 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b 89 88 00 00 00 8b 46 64 88 1c 01 ff 46 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}