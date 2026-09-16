rule Trojan_BAT_Shelma_ASH_MTB_2{
	meta:
		description = "Trojan:BAT/Shelma.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0a 2b 4b 11 04 11 0a 11 04 11 0a 91 11 07 11 0a 1f 20 5d 91 61 d2 9c 11 04 11 0a 11 04 11 0a 91 6e 11 06 11 0a 1f 20 5d 94 6a 59 ?? ?? ?? ?? ?? 6a 5f d2 9c 11 04 11 0a 11 04 11 0a 91 11 05 11 0a 1f 10 5d 91 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 04 8e 69 32 ad } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}