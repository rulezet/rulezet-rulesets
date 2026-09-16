rule Trojan_BAT_Redline_GZZ_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 40 18 5b 06 11 40 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 11 40 18 58 13 40 11 40 06 6f ?? ?? ?? 0a fe 04 13 41 11 41 2d d2 } 		$a_01_1 = {46 75 6e 6e 79 54 68 69 6e 67 41 62 6f 75 74 54 68 61 74 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}