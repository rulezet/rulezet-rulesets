rule Trojan_Win32_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 5c 24 04 89 3c 24 89 f1 ff d5 83 ec 08 89 f0 83 c4 0c 5e 5f 5b 5d } 		$a_01_1 = {03 14 08 ff 74 24 0c 56 ff d2 83 c4 08 89 f0 5e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}