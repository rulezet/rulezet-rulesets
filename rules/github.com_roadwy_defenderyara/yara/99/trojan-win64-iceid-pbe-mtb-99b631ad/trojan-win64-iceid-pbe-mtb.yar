rule Trojan_Win64_IceId_PBE_MTB{
	meta:
		description = "Trojan:Win64/IceId.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f0 11 01 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? ff c8 03 c8 48 8b 83 ?? ?? ?? ?? 31 4b 54 41 8b d0 48 63 8b ?? ?? ?? ?? c1 ea 10 88 14 01 41 8b d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}