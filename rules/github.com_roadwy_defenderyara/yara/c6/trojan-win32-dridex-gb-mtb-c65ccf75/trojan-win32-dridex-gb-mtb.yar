rule Trojan_Win32_Dridex_GB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 32 00 cc [0-04] cc [0-04] cc } 		$a_80_1 = {6c 6c 6f 73 65 77 77 71 2e 6c 6c } 		$a_80_2 = {2e 70 64 62 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=10
 
}