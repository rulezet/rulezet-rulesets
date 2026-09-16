rule Trojan_Win32_Azorult_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 81 [0-09] 01 ?? ?? ?? ?? ?? 83 [0-09] 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}