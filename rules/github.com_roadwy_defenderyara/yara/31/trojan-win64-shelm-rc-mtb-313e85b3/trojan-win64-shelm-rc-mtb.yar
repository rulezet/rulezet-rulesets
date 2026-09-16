rule Trojan_Win64_Shelm_RC_MTB{
	meta:
		description = "Trojan:Win64/Shelm.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 83 f0 45 89 c1 8b 85 8c 00 00 00 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}