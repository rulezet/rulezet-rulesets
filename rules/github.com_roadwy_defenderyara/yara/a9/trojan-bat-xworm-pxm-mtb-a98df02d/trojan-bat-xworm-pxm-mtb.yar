rule Trojan_BAT_XWorm_PXM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 72 85 00 00 70 a2 25 17 08 a2 25 18 72 6a 01 00 70 a2 } 		$a_00_1 = {24 32 33 31 30 66 37 35 30 2d 34 36 66 33 2d 34 35 34 30 2d 39 33 33 62 2d 38 65 35 32 65 63 37 61 35 30 36 38 } 		$a_00_2 = {41 64 64 46 6f 6c 64 65 72 54 6f 44 65 66 65 6e 64 65 72 45 78 63 6c 75 73 69 6f 6e 4c 69 73 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=5
 
}