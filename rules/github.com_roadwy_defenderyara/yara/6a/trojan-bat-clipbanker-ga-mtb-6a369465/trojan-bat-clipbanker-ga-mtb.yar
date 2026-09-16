rule Trojan_BAT_ClipBanker_GA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 2d 6d 61 73 74 65 72 5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 5c [0-32] 2e 70 64 62 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}