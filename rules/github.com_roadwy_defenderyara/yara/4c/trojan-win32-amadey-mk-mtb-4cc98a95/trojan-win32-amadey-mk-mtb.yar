rule Trojan_Win32_Amadey_MK_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d dc 0d 00 00 73 07 cc fa 40 fb cc eb f2 } 		$a_03_1 = {73 07 cc fa 40 fb cc eb f2 90 09 05 00 3d ?? ?? 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}