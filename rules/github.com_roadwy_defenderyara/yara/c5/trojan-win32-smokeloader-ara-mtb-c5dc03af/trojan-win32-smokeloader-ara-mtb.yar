rule Trojan_Win32_SmokeLoader_ARA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 8c 30 4b 13 01 00 a1 ?? ?? ?? ?? 88 0c 30 81 fa ?? ?? ?? ?? 75 3a } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}