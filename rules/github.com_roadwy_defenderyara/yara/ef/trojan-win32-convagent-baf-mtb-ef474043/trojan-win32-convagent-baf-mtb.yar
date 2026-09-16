rule Trojan_Win32_Convagent_BAF_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d8 89 d9 c1 e8 18 c1 e9 0c 31 c1 32 8e ?? ?? ?? ?? 0f b6 d1 8d 8c 24 90 90 00 00 00 e8 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}