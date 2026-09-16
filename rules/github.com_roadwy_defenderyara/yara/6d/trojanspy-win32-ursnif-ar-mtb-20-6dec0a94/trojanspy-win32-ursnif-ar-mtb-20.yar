rule TrojanSpy_Win32_Ursnif_AR_MTB_20{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 75 70 b8 3b 2d 0b 00 01 45 70 8b 45 7c 8b 55 70 8a 14 02 88 14 01 5e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}