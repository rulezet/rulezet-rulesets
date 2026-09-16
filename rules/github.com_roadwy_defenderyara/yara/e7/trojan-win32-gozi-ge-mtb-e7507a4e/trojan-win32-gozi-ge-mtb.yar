rule Trojan_Win32_Gozi_GE_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 03 05 ?? ?? ?? ?? 23 c6 a3 ?? ?? ?? ?? 8d 80 ?? ?? ?? ?? 8a 18 88 10 88 19 0f b6 00 0f b6 cb 03 c8 23 ce 8a 81 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}