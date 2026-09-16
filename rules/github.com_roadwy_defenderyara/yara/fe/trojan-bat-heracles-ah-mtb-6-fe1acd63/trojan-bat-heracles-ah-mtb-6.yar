rule Trojan_BAT_Heracles_AH_MTB_6{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 0d 2b 14 08 11 0d 8f ?? ?? ?? 01 25 47 1e 61 d2 52 11 0d 17 58 13 0d 11 0d 08 8e 69 32 e5 } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}