rule Trojan_Win32_Filecoder_ARA_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 fd 8d 42 7f 99 f7 fd 88 54 34 27 46 83 fe 38 72 dc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}