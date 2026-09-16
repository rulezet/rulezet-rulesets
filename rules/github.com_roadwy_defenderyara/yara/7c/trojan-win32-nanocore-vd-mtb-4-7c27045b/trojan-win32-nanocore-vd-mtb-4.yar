rule Trojan_Win32_NanoCore_VD_MTB_4{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c0 41 89 [0-40] 39 d9 [0-40] 90 13 80 34 01 } 		$a_03_1 = {89 c0 41 89 [0-40] 39 d9 [0-40] 90 13 89 [0-40] 80 34 01 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}