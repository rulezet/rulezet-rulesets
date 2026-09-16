rule Trojan_Win64_Zusy_GZZ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ff c0 48 31 d0 48 c7 c2 ?? ?? ?? ?? 48 31 c0 48 89 05 ?? ?? ?? ?? 4c 01 35 ?? ?? ?? ?? 48 89 f8 50 8f 05 ?? ?? ?? ?? 48 83 f0 ?? 48 31 d0 4c 89 e0 50 8f 05 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}