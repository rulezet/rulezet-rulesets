rule Trojan_Win32_Emotet_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 b9 64 01 00 00 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 43 4d 75 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}