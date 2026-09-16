rule Backdoor_Win32_Remcos_MM_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 01 0f b7 00 f6 c4 f9 74 1e 8b 1d ?? ?? ?? ?? 8b 1b 03 1d ?? ?? ?? ?? 66 25 ff 0f 0f b7 c0 03 d8 a1 ?? ?? ?? ?? 01 03 83 01 02 ff 05 ?? ?? ?? ?? 4a 75 cc } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}