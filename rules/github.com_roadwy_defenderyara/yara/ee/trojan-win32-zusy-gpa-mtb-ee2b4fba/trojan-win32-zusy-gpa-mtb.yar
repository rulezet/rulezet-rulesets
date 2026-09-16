rule Trojan_Win32_Zusy_GPA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 36 ed ff ff 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0 5d } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}