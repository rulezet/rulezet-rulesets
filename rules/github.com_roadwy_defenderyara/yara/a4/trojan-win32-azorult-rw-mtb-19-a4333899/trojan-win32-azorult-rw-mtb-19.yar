rule Trojan_Win32_Azorult_RW_MTB_19{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 52 c0 5d 81 [0-09] 81 [0-09] 8b ?? ?? 8b ?? ?? 8b c2 d3 e0 89 } 		$a_03_1 = {40 2e eb ed 8b 4d ?? 03 cf 89 ?? ?? 8b ?? ?? 8b df d3 eb c7 ?? ?? ?? ?? ?? 2e ce 50 91 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}