rule Trojan_Win32_Ursnif_MTB{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 6c 00 33 f6 90 0a 30 00 66 c7 05 ?? ?? ?? ?? 6b 65 c7 05 ?? ?? ?? ?? 32 2e 64 6c c6 05 ?? ?? ?? ?? 72 c7 05 ?? ?? ?? ?? 6e 65 6c 33 66 c7 05 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}