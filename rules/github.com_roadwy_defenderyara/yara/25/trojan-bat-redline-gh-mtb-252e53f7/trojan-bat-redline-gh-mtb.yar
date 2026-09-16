rule Trojan_BAT_Redline_GH_MTB{
	meta:
		description = "Trojan:BAT/Redline.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 02 11 03 91 61 d2 9c 20 ?? ?? ?? ?? 7e } 		$a_01_1 = {41 00 66 00 6d 00 67 00 75 00 77 00 66 00 7a 00 68 00 69 00 68 00 7a 00 70 00 70 00 77 00 77 00 73 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}