rule Trojan_BAT_Redline_GTT_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 24 11 47 5b 13 29 16 13 4c 2b 39 11 38 11 30 58 13 32 16 13 4d 2b 1e 11 45 11 44 61 13 1d 11 22 11 41 5a 13 37 11 30 6e 11 20 6a 61 6d 13 27 11 4d 17 58 13 4d 11 4d 20 ?? ?? ?? ?? 32 d9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}