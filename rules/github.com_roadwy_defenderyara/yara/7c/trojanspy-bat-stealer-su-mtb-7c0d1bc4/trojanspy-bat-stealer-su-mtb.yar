rule TrojanSpy_BAT_Stealer_SU_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 0a 00 00 04 11 09 11 0b 58 91 08 11 0b 91 2e 05 16 13 0a 2b 0d 11 0b 17 58 13 0b 11 0b 08 8e 69 32 dc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}