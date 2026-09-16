rule Trojan_Win32_StealC_CCJN_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 50 6a 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b f0 33 c9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}