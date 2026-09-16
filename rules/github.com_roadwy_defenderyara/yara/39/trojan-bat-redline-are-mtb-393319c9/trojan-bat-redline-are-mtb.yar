rule Trojan_BAT_Redline_ARE_MTB{
	meta:
		description = "Trojan:BAT/Redline.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e 2c f4 2b 37 00 2b 17 2b 18 2b 1d 9a 6f ?? ?? ?? 0a 14 14 6f ?? ?? ?? 0a 2c 02 de 24 de 10 06 2b e6 6f ?? ?? ?? 0a 2b e1 07 2b e0 26 de 00 1b 2c d3 16 2d c2 07 16 2d 02 17 58 0b 07 1f 0a 32 c4 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}