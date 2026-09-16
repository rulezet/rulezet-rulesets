rule TrojanDownloader_BAT_AgentTesla_KA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 13 06 16 13 07 11 06 12 07 28 1e 00 00 0a 00 08 07 11 05 18 6f 1f 00 00 0a 1f 10 28 20 00 00 0a 6f 21 00 00 0a 00 de 0d 11 07 2c 08 11 06 28 22 00 00 0a 00 dc } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}