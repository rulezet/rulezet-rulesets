rule Trojan_Win32_Filecoder_ARA_MTB_3{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 04 33 f7 d0 88 04 33 83 c6 01 8b 44 24 18 83 d7 00 31 fa 31 f0 09 c2 75 be } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}