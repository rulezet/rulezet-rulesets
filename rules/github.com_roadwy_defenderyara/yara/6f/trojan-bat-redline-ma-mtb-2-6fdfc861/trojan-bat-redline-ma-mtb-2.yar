rule Trojan_BAT_Redline_MA_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 1a 11 19 16 11 19 8e 69 6f 51 00 00 0a 13 1b 06 11 1b 16 11 1b 8e 69 6f 89 00 00 0a de 5b } 		$a_01_1 = {33 37 63 62 36 34 38 61 2d 37 66 64 31 2d 34 35 61 36 2d 39 35 32 35 2d 36 66 64 32 33 62 33 63 34 65 66 39 7d 00 7b 37 35 33 62 32 31 61 31 2d 39 35 33 62 2d 34 35 38 61 2d 38 65 36 35 2d 36 65 34 34 63 39 35 30 31 33 36 66 7d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}