rule Trojan_Win64_Cobaltstrike_AD_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 17 00 00 00 c1 e2 05 8b c2 41 83 e8 2c 4c 0f af c0 49 8b c2 49 f7 e0 48 c1 ea 07 48 69 c2 ff 00 00 00 41 8b d4 4c 2b c0 41 0f b6 c0 0f 45 c8 41 88 0c 39 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}