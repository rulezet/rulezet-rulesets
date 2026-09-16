rule Trojan_Win32_Stelega_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Stelega.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 c0 43 81 c0 ?? ?? ?? ?? 31 0e 48 f7 d3 81 c3 71 f6 8f 39 81 c6 02 00 00 00 89 d8 21 db bb ?? ?? ?? ?? 39 fe 7c } 		$a_03_1 = {29 f0 be a9 d1 a8 fd 31 11 21 f0 81 c6 ?? ?? ?? ?? 09 f6 81 c1 02 00 00 00 81 e8 ?? ?? ?? ?? 39 f9 7c } 		$a_03_2 = {29 f7 81 c7 ?? ?? ?? ?? be 16 2a 95 05 89 f7 31 02 81 c6 ?? ?? ?? ?? 4f 89 f7 81 c2 02 00 00 00 29 f6 be ?? ?? ?? ?? 39 ca 7c } 		$a_03_3 = {29 fe 81 c7 1b 61 0d ee 01 f7 31 11 f7 d6 81 c1 02 00 00 00 29 ff 39 c1 7c ?? 29 ff 4e } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}