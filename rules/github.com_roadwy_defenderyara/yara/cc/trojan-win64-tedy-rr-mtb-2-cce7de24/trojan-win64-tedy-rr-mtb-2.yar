rule Trojan_Win64_Tedy_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 80 30 84 41 80 70 01 85 41 80 70 02 86 41 80 70 03 87 41 80 70 04 88 41 80 70 05 89 41 80 70 06 8a 41 80 70 07 8b 41 80 70 08 8c 41 80 70 09 8d 41 80 70 0a 8e 41 88 78 0c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}