rule TrojanSpy_BAT_Blanajog_A{
	meta:
		description = "TrojanSpy:BAT/Blanajog.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 6a 4c 6f 67 67 65 72 } 		$a_01_1 = {00 4c 61 73 74 41 56 00 } 		$a_01_2 = {00 4c 61 73 74 41 53 00 } 		$a_01_3 = {00 57 52 4b 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}