rule Trojan_Win32_Dridex_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c7 38 7a 0c 01 89 ?? ?? ?? ?? ?? 89 [0-07] b2 ?? f6 ea 8a d8 02 1d ?? ?? ?? ?? 83 c5 04 81 fd 79 20 00 00 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}