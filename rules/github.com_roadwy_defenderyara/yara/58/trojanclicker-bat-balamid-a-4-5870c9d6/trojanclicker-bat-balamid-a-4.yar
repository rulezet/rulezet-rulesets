rule TrojanClicker_BAT_Balamid_A_4{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {2f 72 65 6b 6c 61 6d 2f 90 05 04 03 30 2d 39 78 90 05 04 03 30 2d 39 2e 68 74 6d } 		$a_02_1 = {2f 00 72 00 65 00 6b 00 6c 00 61 00 6d 00 2f 90 05 08 04 00 30 2d 39 00 78 90 05 08 04 00 30 2d 39 00 2e 00 68 00 74 00 6d } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}