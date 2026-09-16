rule Trojan_BAT_NanoCore_VN_MTB_2{
	meta:
		description = "Trojan:BAT/NanoCore.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 00 4d 00 2e 00 4d 00 61 00 69 00 6e 00 } 		$a_01_1 = {50 00 45 00 2e 00 4d 00 61 00 69 00 6e 00 } 		$a_01_2 = {4c 00 6f 00 61 00 64 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}