rule Trojan_Win64_Lazy_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 30 cb 45 0f b6 cb 49 01 f1 45 89 d3 41 c0 fb 07 45 30 d3 45 0f b6 d3 44 0f b6 5c 11 02 44 89 de 40 c0 fe 07 44 30 de 44 0f b6 de 4d 01 d3 4d 01 cb 44 0f b6 4c 11 03 45 89 ca 41 c0 fa 07 45 30 ca } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}