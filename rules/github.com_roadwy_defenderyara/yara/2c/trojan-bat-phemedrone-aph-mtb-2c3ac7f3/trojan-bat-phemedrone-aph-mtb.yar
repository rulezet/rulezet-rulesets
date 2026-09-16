rule Trojan_BAT_Phemedrone_APH_MTB{
	meta:
		description = "Trojan:BAT/Phemedrone.APH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 1c 00 06 07 03 07 91 04 07 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 00 07 17 58 } 		$a_01_1 = {44 65 62 75 67 5c 50 68 65 6d 65 64 72 6f 6e 65 2d 53 74 65 61 6c 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}