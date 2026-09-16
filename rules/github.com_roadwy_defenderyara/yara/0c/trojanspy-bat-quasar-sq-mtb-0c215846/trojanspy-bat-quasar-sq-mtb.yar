rule TrojanSpy_BAT_Quasar_SQ_MTB{
	meta:
		description = "TrojanSpy:BAT/Quasar.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 c4 09 00 00 28 09 00 00 0a 14 0a 17 72 25 02 00 70 12 01 73 0a 00 00 0a 0a 07 2d 05 28 0b 00 00 0a de 0a 07 2c 06 06 6f 0c 00 00 0a dc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}