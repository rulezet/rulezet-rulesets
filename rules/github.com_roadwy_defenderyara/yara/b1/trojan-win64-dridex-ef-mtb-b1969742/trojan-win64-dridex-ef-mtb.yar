rule Trojan_Win64_Dridex_EF_MTB{
	meta:
		description = "Trojan:Win64/Dridex.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {e9 b7 fd ff ff 90 09 31 00 48 89 15 ?? ?? ?? ?? 4c 89 05 ?? ?? ?? ?? 4c 89 0d ?? ?? ?? ?? 4c 89 25 ?? ?? ?? ?? 4c 89 2d ?? ?? ?? ?? 4c 89 35 ?? ?? ?? ?? 4c 89 3d } 		$a_00_1 = {48 83 c1 01 89 94 24 88 00 00 00 48 89 4c 24 50 48 83 f9 25 89 44 24 3c 0f 84 ac 00 00 00 eb 46 8b 44 24 6c 0f af c0 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}