rule Trojan_Win32_Emotet_RT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d1 2b d0 8b [0-05] 8a 18 8a 0c 32 32 d9 8b [0-05] 88 18 8b [0-05] 40 3b c1 89 [0-05] 0f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}