rule TrojanSpy_BAT_Noon_SCK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1d 5d 16 fe 01 0d 09 2c 0b 06 08 06 08 91 1f 4b 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}