rule Trojan_Win64_Rhadamanthys_RR_MTB_3{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 8d 05 [0-05] 89 d9 31 c1 89 c8 31 d0 89 05 ?? ?? ?? ?? eb [0-05] 53 48 83 ec 20 48 89 cb b9 14 00 00 00 e8 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}