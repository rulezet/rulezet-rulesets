rule Trojan_Win32_Zusy_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6b 38 2e 64 6c 6c 00 4a 69 61 6a 6f 69 66 6a 61 65 67 65 61 69 6a 67 64 6a 00 4c 61 69 6f 66 67 6a 61 65 6f 69 67 65 61 67 68 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}