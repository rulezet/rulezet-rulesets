rule Trojan_Win64_FormBook_AFK_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 c9 80 e1 18 44 89 c6 d3 ee 42 8a 4c 1a 04 40 28 f1 0f b6 c9 44 01 d1 42 88 0c 18 49 ff c3 49 ff ca 41 83 c1 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}