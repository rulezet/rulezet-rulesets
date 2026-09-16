rule Trojan_Win32_Fareit_FV_MTB{
	meta:
		description = "Trojan:Win32/Fareit.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 16 8d b6 01 00 00 00 66 23 cd 32 d3 fe ca 80 f2 d7 66 d3 c9 f9 f6 d2 c1 c9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}