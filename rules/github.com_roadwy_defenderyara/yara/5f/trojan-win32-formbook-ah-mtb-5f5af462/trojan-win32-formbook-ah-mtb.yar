rule Trojan_Win32_FormBook_AH_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 eb 86 d9 00 00 58 bb a2 ae 00 00 f7 d2 40 40 f7 d2 81 f3 96 24 01 00 81 eb f4 75 00 00 81 e1 d3 6f 00 00 b8 30 51 00 00 59 81 e1 c7 2d 01 00 48 3d 40 9c 00 00 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}