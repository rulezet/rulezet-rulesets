rule Trojan_Win64_Rhadamanthys_GVD_MTB_2{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 8b 55 d8 48 8b 45 f8 48 01 d0 0f b6 10 48 8b 4d d8 48 8b 45 f8 48 01 c8 83 ea 4c 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 d0 72 d3 } 		$a_01_1 = {48 8b 55 d8 48 8b 45 f0 48 01 d0 0f b6 10 48 8b 4d d8 48 8b 45 f0 48 01 c8 83 f2 39 88 10 4d 8d 6d } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}