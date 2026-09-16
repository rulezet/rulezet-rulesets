rule Trojan_Win32_NanoCore_VD_MTB_5{
	meta:
		description = "Trojan:Win32/NanoCore.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f6 85 d2 [0-40] 8b c3 03 c1 [0-40] 80 30 [0-40] 41 } 		$a_03_1 = {33 d2 f7 f3 85 d2 [0-40] 8b c6 03 c1 [0-40] b2 [0-40] 30 10 [0-40] 41 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}