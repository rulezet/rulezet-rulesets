rule TrojanSpy_AndroidOS_FakeApp_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 73 74 73 2f 73 74 72 61 70 2f 67 72 61 70 68 } 		$a_00_1 = {4e 65 77 73 43 6f 6e 74 65 6e 74 } 		$a_01_2 = {63 6f 6e 74 61 63 74 5f 69 64 20 3d } 		$a_01_3 = {6d 4e 65 78 74 53 65 72 76 65 64 56 69 65 77 } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}