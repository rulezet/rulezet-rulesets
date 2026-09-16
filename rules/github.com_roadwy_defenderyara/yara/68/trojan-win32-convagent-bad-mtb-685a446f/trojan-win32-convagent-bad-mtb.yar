rule Trojan_Win32_Convagent_BAD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 45 08 03 45 f8 0f b6 10 33 94 8d ?? ?? ?? ?? 8b 45 08 03 45 f8 88 10 e9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}