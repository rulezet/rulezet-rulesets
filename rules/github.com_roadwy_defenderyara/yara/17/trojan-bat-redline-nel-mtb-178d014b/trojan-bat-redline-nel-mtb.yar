rule Trojan_BAT_Redline_NEL_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 8f 12 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}