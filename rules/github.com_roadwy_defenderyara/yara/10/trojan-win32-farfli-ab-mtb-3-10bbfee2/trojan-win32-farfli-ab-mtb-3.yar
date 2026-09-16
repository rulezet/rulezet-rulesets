rule Trojan_Win32_Farfli_AB_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 84 05 3c 98 f0 ff 66 0f ef c1 f3 0f 7f 84 05 3c 98 f0 ff 83 c0 10 3d c0 67 0f 00 75 e0 } 		$a_01_1 = {46 69 6c 65 20 63 72 65 61 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}