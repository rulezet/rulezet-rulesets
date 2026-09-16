rule Trojan_Win64_Rhadamanthys_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8d [0-05] 0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 4d 8d 36 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}