rule TrojanProxy_BAT_Banker_G{
	meta:
		description = "TrojanProxy:BAT/Banker.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 64 62 22 20 28 73 74 61 72 74 20 2f 6c 6f 77 20 2f 6d 69 6e 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 22 68 74 74 70 3a 2f 2f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}