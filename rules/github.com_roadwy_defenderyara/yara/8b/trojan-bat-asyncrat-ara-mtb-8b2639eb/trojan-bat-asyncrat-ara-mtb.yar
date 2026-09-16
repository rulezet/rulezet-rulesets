rule Trojan_BAT_AsyncRAT_ARA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 b4 9c [0-02] 03 6f 2a 00 00 0a 17 da 33 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}