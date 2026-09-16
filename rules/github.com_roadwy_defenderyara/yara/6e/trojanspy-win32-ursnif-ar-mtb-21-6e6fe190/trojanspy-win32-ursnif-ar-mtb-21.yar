rule TrojanSpy_Win32_Ursnif_AR_MTB_21{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 94 06 3b 2d 0b 00 88 14 01 5e 8b e5 5d } 		$a_01_1 = {b8 bb df 9f 03 f7 a5 a8 fe ff ff 8b 85 a8 fe ff ff b8 ed 2b b0 26 f7 a5 28 ff ff ff 8b 85 28 ff ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}