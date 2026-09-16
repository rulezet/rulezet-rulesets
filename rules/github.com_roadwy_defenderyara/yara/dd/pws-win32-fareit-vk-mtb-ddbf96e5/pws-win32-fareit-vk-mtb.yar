rule PWS_Win32_Fareit_VK_MTB{
	meta:
		description = "PWS:Win32/Fareit.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {58 52 81 ca ?? ?? ?? ?? 5a 51 81 f1 ?? ?? ?? ?? 59 8f 04 18 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}