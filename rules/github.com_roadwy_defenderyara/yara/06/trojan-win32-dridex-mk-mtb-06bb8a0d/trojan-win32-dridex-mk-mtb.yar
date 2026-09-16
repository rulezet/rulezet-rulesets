rule Trojan_Win32_Dridex_MK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 12 35 09 00 77 07 cc cc cc 40 cc eb f2 } 		$a_03_1 = {77 07 cc cc cc 40 cc eb f2 90 09 05 00 3d ?? ?? ?? 00 } 	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}