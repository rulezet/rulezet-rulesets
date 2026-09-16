rule Trojan_Win64_IcedID_MA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 83 c1 04 44 0f af 83 94 00 00 00 8b 43 6c 05 ?? ?? ?? ?? 03 c8 01 4a 2c 8b 83 a4 00 00 00 41 8b d0 33 05 ?? ?? ?? ?? 2d ?? ?? ?? ?? c1 ea 10 01 83 8c 00 00 00 48 63 8b 98 00 00 00 48 8b 83 c8 00 00 00 88 14 01 41 8b d0 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}