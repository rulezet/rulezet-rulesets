rule TrojanProxy_Win32_Bedri_C{
	meta:
		description = "TrojanProxy:Win32/Bedri.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ff 73 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 39 c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 78 } 		$a_03_1 = {ff ff 62 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 33 c6 85 ?? ?? ff ff 68 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 62 } 		$a_01_2 = {3c 62 6f 64 79 3e 3c 68 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 68 31 3e 3c 2f 62 6f 64 79 3e } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}